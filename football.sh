#!/bin/bash
#
# This file is part of MARS project: http://schoebel.github.io/mars/
#
# Copyright (C) 2017 Thomas Schoebel-Theuer
# Copyright (C) 2017 1&1 Internet AG
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

############################################################

# Container Football

# TST started in summer 2017

# Generic MARS background migration of a VM / container.
# Plugins can be used for adaptation to system-specific sub-operations
# (e.g. the 1&1-specific clustermanager cm3, or for interfacing with
# the mass-parallelism handler "screener.sh")

# There are some basic conventions / assumptions:
#   - MARS resource names are equal to LV names and to KVM / LXC names
#   - All hosts are in DNS with their pure names (accessible via resolv.conf)
#     [consequence: all host names are globally disjoint]
#   - There is a 1:n relationship between each
#        $storage_host : $hypervisor_host : $container_host

set -o pipefail
shopt -s nullglob
export LC_ALL=C
export start_stamp="$(date "+%F_%T" | sed 's/:/./g')"

function list_union
{
    local list1="$1"
    local list2="$2"

    local -A exists=()
    local i
    for i in $list1 $list2; do
	(( exists[$i] )) && continue
	echo "$i"
	exists[$i]=1
    done
}

function list_minus
{
    local list1="$1"
    local list2="$2"

    local -A exists=()
    local i
    for i in $list2; do
	exists[$i]=1
    done
    for i in $list1; do
	(( exists[$i] )) && continue
	echo "$i"
	exists[$i]=1
    done
}

function commands_installed
{
    local cmd_list="$1"

    local cmd
    for cmd in $cmd_list; do
	if ! which $cmd > /dev/null; then
	    fail "shell command '$cmd' is not installed"
	fi
    done
}

# common *.conf and *.sh include infrastructure
script_dir="$(dirname "$(which "$0")")"

## football_includes
# List of directories where football-*.sh and football-*.conf
# files can be found.
football_includes="${football_includes:-/usr/lib/mars/plugins /etc/mars/plugins $script_dir/plugins $HOME/.mars/plugins ./plugins}"

## football_confs
# Another list of directories where football-*.conf files can be found.
# These are sourced in a second pass after $football_includes.
# Thus you can change this during the first pass.
football_confs="${football_confs:-/usr/lib/mars/confs /etc/mars/confs $script_dir/confs $HOME/.mars/confs ./confs}"

declare -g -A files=()
declare -g file
declare -g module_list=""
declare -g description_list=""
declare -g plugin_command_list=""

function register_module
{
    local module="$1"

    if [[ "$module" != "" ]]; then
	files[$module]="$file"
	module_list+=" $module"
    fi
}

function register_command
{
    local command_list="$1"

    if [[ "$command_list" != "" ]]; then
	plugin_command_list+=" $command_list"
    fi
}

function register_description
{
    local description="$1"

    if [[ "$description" != "" ]]; then
	files[$description]="$file"
	description_list+=" $description"
    fi
}

function get_cred_file
{
    local glob="$1"

    local dir
    for dir in $football_confs $football_includes; do
	local file
	for file in $dir/$glob; do
	    if [[ -r "$file" ]]; then
		echo "$file"
		return
	    fi
	done
    done
}

# Sourcing of config files and modules in multiple passes

function source_glob
{
    local dirs="$1"
    local pattern="$2"
    local txt="$3"
    local abort="${4:-1}"

    local dir
    for dir in $dirs; do
	local file
	for file in $(eval "echo $dir/$pattern"); do
	    if ! [[ -r "$file" ]]; then
		echo "$txt: file '$file' is not readable" >> /dev/stderr
		continue
	    fi
	    if (( verbose )); then
		echo "$txt: sourcing $file" >> /dev/stderr
	    fi
	    if ! source "$file"; then
		echo "Cannot source '$file'" >> /dev/stderr
		if (( abort )); then
		    exit -1
		fi
	    fi
	done
    done
}

source_glob "$football_confs"    "football-*.preconf"  "Pass1a"
source_glob "$football_includes" "football-*.preconf"  "Pass1b"
source_glob "$football_confs"    "football-*.conf"     "Pass2a"
source_glob "$football_includes" "football-*.conf"     "Pass2b"
source_glob "$football_includes" "infra-*.sh"          "Pass3"
source_glob "$football_includes" "football-*.sh"       "Pass4"
source_glob "$football_confs"    "football-*.postconf" "Pass5a"
source_glob "$football_includes" "football-*.postconf" "Pass5b"
source_glob "$football_confs"    "football-*.reconf"   "Pass6a"
source_glob "$football_includes" "football-*.reconf"   "Pass6b"

# parameters
# normally given on the command line.

operation="${operation:-}"
res="${res:-}"
target_primary="${target_primary:-}"
target_secondary="${target_secondary:-}"
target_percent=${target_percent:-85}

# short options

## dry_run
# When set, actions are only simulated.
dry_run=${dry_run:-0}

## verbose
# increase speakiness.
verbose=${verbose:-0}

## confirm
# Only for debugging: manually started operations can be
# manually checked and confirmed before actually starting opersions.
confirm=${confirm:-1}

## force
# Normally, shrinking and extending will only be started if there
# is something to do.
# Enable this for debugging and testing: the check is then skipped.
force=${force:-0}

## debug_injection_point
# RTFS don't set this unless you are a developer knowing what you are doing.
debug_injection_point="${debug_injection_point:-0}"

## football_logdir
# Where the logfiles should be created.
# HINT: after playing Football in masses for a whiile, your $logdir will
# be easily populated with hundreds or thousands of logfiles.
# Set this to your convenience.
football_logdir="${football_logdir:-${logdir:-$HOME/football-logs}}"

## screener
# When enabled, handover execution to the screener.
# Very useful for running Football in masses.
screener="${screener:-0}"

## min_space
# When testing / debugging with extremely small LVs, it may happen
# that mkfs refuses to create extemely small filesystems.
# Use this to ensure a minimum size.
min_space="${min_space:-20000000}"

## cache_repeat_lapse
# When using the waiting capabilities of screener, and when waits
# are lasting very long, your dentry cache may become cold.
# Use this for repeated refreshes of the dentry cache after some time.
cache_repeat_lapse="${cache_repeat_lapse:-120}" # Minutes

# more complex options

## remote_ping
# Before using ssh, ping the target.
# This is only useful in special cases.
remote_ping="${remote_ping:-0}"

## ping_opts
# Options for ping checks.
ping_opts="${ping_opts:--W 1 -c 1}"

## ssh_opt
# Useful for customization to your ssh environment.
ssh_opt="${ssh_opt:--4 -A -o StrictHostKeyChecking=no -o ForwardX11=no -o KbdInteractiveAuthentication=no -o VerifyHostKeyDNS=no}"

## rsync_opt
# The rsync options in general.
# IMPORTANT: some intermediate progress report is absolutely needed,
# because otherwise a false-positive TIMEOUT may be assumed when
# no output is generated for several hours.
rsync_opt="${rsync_opt:- -aSH --info=progress2,STATS}"

## rsync_opt_prepare
# Additional rsync options for preparation and updating
# of the temporary shrink mirror filesystem.
rsync_opt_prepare="${rsync_opt_prepare:---exclude='.filemon2' --delete}"

## rsync_opt_hot
# This is only used at the final rsync, immediately before going
# online again.
rsync_opt_hot="${rsync_opt_hot:---delete}"

## rsync_nice
# Typically, the preparation steps are run with background priority.
rsync_nice="${rsync_nice:-nice -19}"

## rsync_repeat_prepare and rsync_repeat_hot
# Tuning: increases the reliability of rsync and ensures that the dentry cache
# remains hot.
rsync_repeat_prepare="${rsync_repeat_prepare:-5}"
rsync_repeat_hot="${rsync_repeat_hot:-3}"

## wait_timeout
# Avoid infinite loops upon waiting.
wait_timeout="${wait_timeout:-$(( 24 * 60 ))}" # Minutes

## lvremove_opt
# Some LVM versions are requiring this for unattended batch operations.
lvremove_opt="${lvremove_opt:--f}"

## automatic recovery options: enable_failure_*
enable_failure_restart_vm="${enable_failure_restart_vm:-1}"
enable_failure_recreate_cluster="${enable_failure_recreate_cluster:-0}"
enable_failure_rebuild_mars="${enable_failure_rebuild_mars:-1}"

## critical_status
# This is the "magic" exit code indicating _criticality_
# of a failed command.
critical_status="${critical_status:-199}"

## serious_status
# This is the "magic" exit code indicating _seriosity_
# of a failed command.
serious_status="${serious_status:-198}"

## tmp_suffix
# Only for experts.
tmp_suffix="${tmp_suffix:--tmp}"

## shrink_suffix_old
# Suffix for backup LVs. These are kept for wome time until
# *_cleanup operations will remove them.
shrink_suffix_old="${shrink_suffix_old:--preshrink}"


# some constants
commands_needed="${commands_needed:-ssh rsync grep sed awk sort head tail tee cat ls basename dirname cut ping date mkdir rm wc bc}"

######################################################################

# help

function show_vars
{
    local script="$1"

    if (( !verbose )); then
	return
    fi

    local matches=0
    local line
    while read line; do
	if [[ "$line" =~ ^\#\#\  ]]; then
	    matches=1
	elif [[ "$line" = "" ]]; then
	    (( matches )) && echo ""
	    matches=0
	fi
	if (( matches )); then
	    echo "  $line"
	fi
    done < "$script"
}

function helpme
{
    cat <<EOF
Usage:
  $0 --help [--verbose]
     Show help
  $0 --variable=<value>
     Override any shell variable

Actions for resource migration:

  $0 migrate         <resource> <target_primary> [<target_secondary>]
     Run the sequence
     migrate_prepare ; migrate_wait ; migrate_finish; migrate_cleanup.

Dto for testing (do not rely on it):

  $0 migrate_prepare <resource> <target_primary> [<target_secondary>]
     Allocate LVM space at the targets and start MARS replication.

  $0 migrate_wait    <resource> <target_primary> [<target_secondary>]
     Wait until MARS replication reports UpToDate.

  $0 migrate_finish  <resource> <target_primary> [<target_secondary>]
     Call hooks for handover to the targets.

  $0 migrate_cleanup <resource>
     Remove old / currently unused LV replicas from MARS and deallocate
     from LVM.

  $0 manual_migrate_config  <resource> <target_primary> [<target_secondary>]
     Transfer only the cluster config, without changing the MARS replicas.
     This does no resource stopping / restarting.
     Useful for reverting a failed migration.

  $0 manual_config_update <hostname>
     Only update the cluster config, without changing anything else.
     Useful for manual repair of failed migration.


Actions for inplace FS shrinking:

  $0 shrink          <resource> <percent>
     Run the sequence shrink_prepare ; shrink_finish ; shrink_cleanup.

Dto for testing (do not rely on it):

  $0 shrink_prepare  <resource> [<percent>]
     Allocate temporary LVM space (when possible) and create initial
     raw FS copy.
     Default percent value(when left out) is $target_percent.

  $0 shrink_finish   <resource>
     Incrementally update the FS copy, swap old <=> new copy with
     small downtime.

  $0 shrink_cleanup  <resource>
     Remove old FS copy from LVM.

Actions for inplace FS extension:

  $0 extend          <resource> <percent>

Combined actions:

  $0 migrate+shrink <resource> <target_primary> [<target_secondary>] [<percent>]
     Similar to migrate ; shrink but produces less network traffic.
     Default percent value (when left out) is $target_percent.

Global maintenance:

  $0 lv_cleanup      <resource>

General features:

  - Instead of <percent>, an absolute amount of storage with suffix
    'k' or 'm' or 'g' can be given.

  - When <resource> is currently stopped, login to the container is
    not possible, and in turn the hypervisor node and primary storage node
    cannot be automatically determined. In such a case, the missing
    nodes can be specified via the syntax
        <resource>:<hypervisor>:<primary_storage>

  - The following LV suffixes are used (naming convention):
    $tmp_suffix = currently emerging version for shrinking
    $shrink_suffix_old = old version before shrinking took place

  - By adding the option --screener, you can handover football execution
    to $(dirname "$0")/screener.sh .
    When some --enable_*_waiting is also added, then the critical
    sections involving customer downtime are temporarily halted until
    some sysadmins says "screener.sh continue \$resource" or
    attaches to the sessions and presses the RETURN key.

EOF
   show_vars "$0"
   call_hook describe_plugin
}

######################################################################

# basic infrastructure

failure_handler=""
recursive_failure=0

function fail
{
    local txt="${1:-Unkown failure}"
    local status="${2:--1}"

    unset exit
    echo "=====================================================" >> /dev/stderr
    echo "FAIL pid=$BASHPID status=$status '$txt'" >> /dev/stderr

    if (( recursive_failure )); then
	echo "RECURSIVE_FAILURE (now $status): $txt" >> /dev/stderr
	status="$recursive_failure"
	failure_handler=""
    elif (( critical_section && critical_status )); then
	echo "FAILURE_IN_CRITICAL_SECTION" >> /dev/stderr
    else
	echo "FAILURE (status=$status): $txt" >> /dev/stderr
    fi
    if [[ "$failure_handler" != "" ]] && [[ "$BASHPID" = "$main_pid" ]]; then
	echo "STARTING FAILURE HANDLER '$failure_handler'" >> /dev/stderr
	recursive_failure="${serious_status:-$status}"
	$failure_handler
	local status=$?
	echo "FINISHED FAILURE HANDLER '$failure_handler' status=$status" >> /dev/stderr
    fi
    if (( recursive_failure && serious_status && !status )); then
	echo "FAILING with serious_status=$serious_status" >> /dev/stderr
	status="$serious_status"
    elif (( critical_section && critical_status )); then
	echo "FAILING with critical_status=$critical_status" >> /dev/stderr
	status="$critical_status"
    else
	echo "FAILING with status=$status" >> /dev/stderr
    fi
    if [[ "$BASHPID" = "$main_pid" ]]; then
	echo "" >> /dev/stderr
	echo "EXIT status=$status" >> /dev/stderr
    fi
    unset exit
    exit $status
}

# override the standard exit function for detection of recursion
function exit
{
    local status="${1:-0}"

    unset exit
    if (( status || recursive_failure )); then
	fail "exit $status" "$status"
    fi
    if [[ "$BASHPID" = "$main_pid" ]]; then
	call_hook 0 football_finished "$status" "$0" "$@"
    fi
    echo "EXIT status=$status" >> /dev/stderr
    exit $status
}

# Unfortunately, the bash has no primitive for running an arbitrary
# (complex) command until some timeout is exceeded.
#
# Workaround by disjoint waiting for an additional background sleep process.
#
function timeout_cmd
{
    local cmd="$1"
    local limit="${2:-30}"
    local do_fail="${3:-0}"

    if (( limit <= 0 )); then # timeout is disabled
        bash -c "$cmd"
        local rc=$?
        #echo "RC=$rc" >> /dev/stderr
        return $rc
    fi

    set +m
    eval "$cmd" &
    local cmd_pid=$!

    sleep $limit &
    local sleep_pid=$!

    # disjoint waiting
    wait -n $cmd_pid $sleep_pid
    local rc1=$?
    #echo "RC1=$rc1" >> /dev/stderr

    kill $sleep_pid > /dev/null 2>&1
    kill $cmd_pid > /dev/null 2>&1
    wait $cmd_pid > /dev/null 2>&1
    local rc2=$?
    #echo "RC2=$rc2" >> /dev/stderr

    # ensure to eat the background status, +m alone is not enough
    wait $sleep_pid > /dev/null 2>&1

    if (( rc2 == 143 )); then
	if (( do_fail )); then
	    fail "TIMEOUT $limit seconds for '$cmd' reached"
	else
	    echo "TIMEOUT $limit seconds for '$cmd' reached" >> /dev/stderr
	fi
    fi

    local rc=$(( rc1 | rc2 ))
    #echo "RC=$rc" >> /dev/stderr
    return $rc
}

args_info=""

function scan_args
{
    local -a params
    local index=0
    local par
    for par in "$@"; do
	if [[ "$par" = "--help" ]]; then
	    operation=help
	    continue
	elif [[ "$par" =~ "=" ]]; then
	    par="${par#--}"
	    local lhs="$(echo "$par" | cut -d= -f1)"
	    local rhs="$(echo "$par" | cut -d= -f2-)"
	    lhs="${lhs//-/_}"
	    echo "$lhs=$rhs"
	    eval "$lhs=$rhs"
	    continue
	elif [[ ":$par" =~ ":--" ]]; then
	    par="${par#--}"
	    par="${par//-/_}"
	    echo "$par=1"
	    eval "$par=1"
	    continue
	fi
	if (( !index )); then
	    if [[ "$par" =~ migrate_cleanup|lv_cleanup ]]; then
		local -a params=(operation res)	
	    elif [[ "$par" =~ migrate ]]; then
		local -a params=(operation res target_primary target_secondary)
	    elif [[ "$par" =~ shrink|extend ]]; then
		local -a params=(operation res target_percent)
	    elif [[ "$par" =~ manual_config_update ]]; then
		local -a params=(operation host)
	    else
		helpme
		fail "unknown operation '$1'"
	    fi
	fi
	# Treat a single number always as target_percent
	if [[ "$par" =~ ^[0-9]+$ ]]; then
	    echo "Setting target_percent from $target_percent to $par"
	    target_percent="$par"
	    continue
	fi
	local lhs="${params[index]}"
	if [[ "$lhs" != "" ]]; then
	    echo "$lhs=$par"
	    eval "$lhs=$par"
	    args_info+=".${par//:/_}"
	    (( index++ ))
	else
	    helpme
	    fail "stray parameter '$par'"
	fi
    done
    if [[ "$operation" = "help" ]]; then
	helpme
	exit 0
    fi
}

function do_confirm
{
    local skip="$1"
    local response

    (( !confirm )) && return 0

    [[ "$skip" != "" ]] && skip="S to skip, "
    echo -n "[CONFIRM: Press ${skip}Return to continue, ^C to abort] "
    read -e response
    ! [[ "$response" =~ ^[sS] ]]
    return $?
}

function remote
{
    local login="$1" # syntax username@hostname is allowed
    local cmd="$2"
    local nofail="${3:-0}"

    local host="${login##*@}"
    local port="$(call_hook ssh_port "$host" 2>/dev/null)"
    if (( verbose > 0 )); then
	echo "Executing on $host $port: '$cmd'" >> /dev/stderr
    fi

    call_hook ssh_indirect "$host" "$cmd" </dev/null >/dev/null 2>&1
    local indirect="$(call_hook ssh_indirect "$host" "$cmd" </dev/null)"
    if [[ "$indirect" != "" ]]; then
	host="${indirect%%:*}"
	login="root@$host"
	cmd="${indirect#*:}"
	port="$(call_hook ssh_port "$host" 2>/dev/null)"
	if (( verbose > 0 )); then
	    echo "Indirection to $host $port: '$cmd'" >> /dev/stderr
	fi
    fi

    [[ "$host" = "" ]] && return
    [[ "${cmd## }" = "" ]] && return

    if ! [[ "$login" =~ @ ]]; then
	login="root@$host"
    fi

    # Avoid long ssh timeouts by pinging first
    local rc=0
    local retry="$remote_ping"
    while (( retry > 0 )); do
	if ping $ping_opts "${login##*@}" > /dev/null; then
	    rc=0
	    break
	fi
	echo "Host '${login##*@}' does not ping (retry=$retry)" >> /dev/stderr
	rc=1
	sleep 1
	(( retry-- ))
    done

    if (( !rc )); then
	ssh $port $ssh_opt "$login" "$cmd"
	rc=$?
    fi
    if (( !rc )); then
	return 0
    elif (( nofail )); then
	return $rc
    else
	fail "ssh to '$host' command '$cmd' failed with status $rc"
    fi
}

function log
{
    local dir="$1"
    local file="$2"

    if [[ "$dir" != "" ]] && [[ "$file" != "" ]]; then
	tee -a "$dir/$file"
    else
	cat
    fi
}

section_nr=1

function section
{
    local txt="${1:--}"
    echo ""
    echo "==================================================================="
    echo "$(( section_nr++ )). $txt"
    echo ""
}

function exists_hook
{
    local name="$1"

    local module
    for module in $module_list; do
	if [[ "$(type -t "${module}_$name")" =~ function ]]; then
	    return 0
	fi
    done
    return 1
}

# GENERIC calls to _any_ number of defined hook functions having their
# module name as a prefix. This way, multiple plugins can co-exist.
# When no callee is defined, nothing happens.
# When multiple callees are defined (e.g. in different plugins), _all_
# of them are called, in module initialization order.

function call_hook
{
    local abort=1
    # OPTIONAL: when the first argument is 0, don't abort on errors
    if [[ "$1" =~ ^[0-9]+$ ]]; then
	abort=$1
	shift
    fi
    local name="$1"
    shift

    local called=0
    local status=0
    local module
    for module in $module_list generic; do
	local m_name="${module}_$name"
	if [[ "$(type -t "$m_name")" =~ function ]]; then
	    if (( verbose )); then
		echo "Running hook: $m_name $@" >> /dev/stderr
	    fi
	    if (( abort )); then
		$m_name "$@"
	    else
		($m_name "$@")
	    fi
	    local rc="$?"
	    (( status |= rc ))
	    if (( verbose )); then
		echo "hook '$m_name $@' rc=$rc" >> /dev/stderr
	    fi
	    if (( rc )); then
		if (( abort )); then
		    fail "cannot execute hook function '$m_name'"
		else
		    echo "failed hook function '$m_name', rc=$rc" >> /dev/stderr
		fi
	    fi
	    (( called++ ))
	fi
    done
    if (( verbose && !called )); then
	echo "Skipping undefined hook '$name'"  >> /dev/stderr
    fi
    return $status
}

######################################################################

# helper functions for determining hosts / relationships

declare -g -A hypervisor_host=()

function get_hyper
{
    local res="$1"

    declare -g hypervisor_host
    local hyper="${hypervisor_host[$res]}"
    if [[ "$hyper" = "" ]]; then
	hyper="$(call_hook get_hyper "$res")" ||\
	    fail "Cannot determine hypervisor hostname for resource '$res'"
	hypervisor_host[$res]="$hyper"
    fi
    [[ "$hyper" = "" ]] && return -1
    echo "$hyper"
}

declare -g -A storage_host=()

function get_store
{
    local res="$1"

    declare -g storage_host
    local store="${storage_host[$res]}"
    if [[ "$store" = "" ]]; then
	store="$(call_hook get_store "$res")" ||\
	    fail "Cannot determine storage hostname for resource '$res'"
	if [[ "$store" = "" ]]; then
	    # assume local storage
	    store="$(get_hyper "$res")"
	fi
	storage_host[$res]="$store"
    fi
    [[ "$store" = "" ]] && return -1
    echo "$store"
}

declare -A vgs

function get_vg
{
    local host="$1"

    declare -g vgs
    local vg="${vgs[$host]}"
    if [[ "$vg" = "" ]]; then
	vg="$(call_hook get_vg "$host")" ||\
	    fail "Cannot determine volume group for host '$host'"
	vgs[$host]="$vg"
    fi
    [[ "$vg" = "" ]] && return -1
    echo "$vg"
}

######################################################################

# further helpers

safeguard_delete_resource="${safeguard_delete_resource:-2}"

function safeguard_deleted
{
    local host_list="$1"

    if (( !safeguard_delete_resource )); then
	return
    fi

    local host
    for host in $host_list; do
	remote "$host" "marsadm wait-cluster" &
    done
    wait
    for host in $host_list; do
	remote "$host" "for i in \$(find /mars/ -name \".deleted-*\"); do ls -l \$i; rm -f \$i; done" &
    done
    wait
}

function get_full_list
{
    local host_list="$1"
    local with_hyper="${2:-0}"

    local full_list=""
    while true; do
	full_list="$(echo $(for host in $host_list; do echo $host; if (( with_hyper )); then call_hook get_hyper $host; get_store $host; fi; remote "$host" "marsadm view-cluster-members" 1; done | sort -u) )"
	[[ "$full_list" = "$host_list" ]] && break
	host_list="$full_list"
    done
    echo $full_list
}

function leave_resource
{
    local res="$1"
    local host_list="$2"

    host_list="${host_list## }"
    host_list="${host_list%% }"
    host_list="${host_list//  / }"
    local host_glob="{${host_list// /,}}"
    [[ "$host_glob" =~ , ]] || host_glob="$host_list"
    local full_list="$(get_full_list "$host_list")"

    local retry
    for (( retry=0; retry < 10; retry++ )); do
	safeguard_deleted "$host_list"
	local cmd
	local host
	for host in $host_list; do
	    cmd="marsadm down $res || marsadm down --force $res || echo IGNORE"
	    cmd+="; marsadm leave-resource $res || echo IGNORE"
	    cmd+="; marsadm leave-resource --force $res || echo IGNORE"
	    remote "$host" "$cmd"
	done
	if (( safeguard_delete_resource > 1 )); then
	    for host in $full_list; do
		remote "$host" "marsadm wait-cluster" &
	    done
	    wait
	    for host in $full_list; do
		remote "$host" "rm -f /mars/resource-$res/{data,replay,version-*,.deleted-*}-$host_glob" &
	    done
	    wait
	    sleep 10
	fi
	local count=0
	for host in $full_list; do
	    cmd="ls -l /mars/resource-$res/{data,replay}-$host_glob | tee /dev/stderr | wc -l"
	    (( count += $(remote "$host" "$cmd") ))
	done
	(( !count )) && return 0
	echo "LEFT $count: REPEAT delete-resource $host_list"
	sleep 7
	echo "RETRY $retry leave-resource" 
    done
    fail "leave-resource $res did not work on $host_list"
}

function delete_resource
{
    local res="$1"
    local host_list="$2"

    local full_list="$(get_full_list "$host_list")"

    local retry
    for (( retry=0; retry < 3; retry++ )); do
	local host
	leave_resource "$res" "$full_list"
	if (( !safeguard_delete_resource )) && [[ "$primary" != "" ]]; then
	    remote "$primary" "marsadm delete-resource $res"
	else
	    safeguard_deleted "$full_list"
	    for host in $full_list; do
		remote "$host" "marsadm delete-resource --force $res" &
	    done
	    wait
	fi
	sleep 16
	local has_remains=0
	for host in $full_list; do
	    local count="$(remote "$host" "shopt -s nullglob; ls /mars/resource-$res/{replay,data}-*"  | wc -l)"
	    echo "Host '$host' has '$count' remains"
	    if (( count )); then
		(( has_remmains++ ))
	    fi
	done
	if (( !has_remains )); then
	    return
	fi
	echo "RETRY $retry delete-resource" 
    done
}

function wait_for_screener
{
    local res="$1"
    local situation="$2"
    local mode="${3:-waiting}"
    local msg="${4:-$operation}"
    local timeout="${5:-$wait_timeout}"
    local repeat_lapse="${6:-0}"
    local lapse_cmd="${7:-uptime}"
    shift 7

    local enable="enable_${situation}_${mode}"
    if (( !$enable )); then
	echo "$enable is off"
    fi
    echo "$enable is on"

    local hot_round=0
    local total_round=0
    local reset_freq=0
    if (( $enable )); then
	call_hook start_wait "$res" "$mode" "$situation: $msg"
    fi
    while true; do
	local locked="$(verbose=0 call_hook resource_locked "$res")"
	local poll=0
	if (( $enable )); then
	    poll="$(verbose=0 call_hook poll_wait "$res" "$mode" 0 $reset_freq)"
	fi
	if (( !poll && !locked )); then
	    return
	fi
	if (( timeout > 0 && total_round > timeout + 1 )); then
	    break
	fi
	local keypress=0
	if [[ -t 0 ]]; then
	    if (( !hot_round )); then
		echo "Press RETURN to interrupt / shorten the $mode (${total_round}m/${timeout}m)"
	    fi
	    local i
	    local dummy
	    for (( i = 0; i < 60; i++ )); do
		read -t 1 dummy
		keypress=$(( !$? ))
		(( keypress )) && break
	    done
	else
	    sleep 60
	fi
	reset_freq=0
	(( hot_round++ ))
	(( total_round++ ))
	if (( repeat_lapse > 0 && hot_round >= repeat_lapse )); then
	    hot_round=0
	    $lapse_cmd "$@"
	    reset_freq=1
	fi
	if (( timeout > 0 && total_round >= timeout )); then
	    echo "TIMEOUT SCREENER_$mode $(date +%s) $(date)"
	    call_hook poll_wait "$res" "$mode" 1 1
	elif (( keypress )); then
	    echo "KEYPRESS SCREENER_$mode $(date +%s) $(date)"
	    call_hook poll_wait "$res" "$mode" 1 1
	fi
    done
}

# debugging: failure injection for testing of idempotence

declare -g injection_nr=0

function injection_point
{
    (( injection_nr++ ))
    if (( debug_injection_point )); then
	echo "INJECTION point $injection_nr"
	if (( injection_nr >= debug_injection_point && debug_injection_point > 0 )); then
	    fail "INJECTION_POINT $debug_injection_point has triggered"
	fi
    fi
}

######################################################################

# Compensation actions upon failures.
# Try to KTLO = Keep The Lights On
# by restarting services before error exit

failure_restart_primary=""
failure_restart_hyper=""
failure_restart_vm=""

function failure_restart_vm
{
    local primary_list="${1:-$failure_restart_primary}"
    local hyper="${2:-failure_restart_hyper}"
    local res="${3:-$res}"

    if (( enable_failure_restart_vm )) && \
	[[ "$res" != "" ]]; then
	if [[ "$primary_list" = "" ]] && [[ "$hyper" != "" ]]; then
	    # Last resort.
	    # Assume that the hypervisor is working and try to work there
	    section "EMERGENCY try to restart hyper='$hyper' resource='$res'"

	    # try to get a defined state
	    call_hook 0 resource_stop_vm "$hyper" "$res" || echo IGNORE
	    # try to start twice
	    if ! call_hook 0 resource_start_vm "$hyper" "$res"; then
		call_hook 0 resource_stop_vm "$hyper" "$res" || echo IGNORE
		call_hook resource_start_vm "$hyper" "$res"
	    fi
	    return
	fi
	local -A tried=()
	local primary
	for primary in $primary_list; do
	    (( tried[$primary] )) && continue
	    section "EMERGENCY check whether restart primary='$primary' resource='$res' is possible"
	    if [[ "$(call_hook is_startable "$primary" "$res" | tee -a /dev/stderr | tail -1)" != "1" ]]; then
		echo "Startup of $res is reported as not possible at $primary".
		echo "If this is wrong, fix configs by hand."
		continue
	    fi
	    (( tried[$primary]++ ))
	    local retry
	    for (( retry=0; retry < 3; retry++ )); do
		section "EMERGENCY try to restart primary='$primary' resource='$res'"

		# try to get a defined state
		call_hook 0 resource_stop "$primary" "$res" ||
		call_hook 0 resource_stop "$primary" "$res" || echo IGNORE

		# try to restart
		if ! call_hook 0 resource_start "$primary" "$res"; then
		    call_hook 0 resource_stop "$primary" "$res"
		    call_hook 0 resource_start "$primary" "$res"
		fi
		if (( !$? )); then
		    return
		fi
		# check whether the cluster config is recent
		if (( enable_failure_recreate_cluster )); then
		    # Brute force... hopefully it will help
		    local other
		    for other in $primary_list; do
			declare -g always_migrate=$(( retry > 0 ))
			if call_hook 0 update_cm3_config "$other" "$primary" "$res"; then
			    sleep 10
			    break
			fi
		    done
		fi
	    done
	done
    fi
    fail "cannot restart vm='$res' at primary_list='$primary_list'"
}

function failure_rebuild_mars
{
    local primary_list="${1:-$failure_restart_primary}"
    local hyper="${2:-failure_restart_hyper}"
    local res="${3:-$res}"

    [[ "$primary_list" = "" ]] && return
    [[ "$res" = "" ]] && return

    if (( enable_failure_rebuild_mars )); then
	# Assuption: at least some usable LV must exist.
	# Don't try to rename anything. In case of emergency, just use
	# everything which looks plausible.

	local lv
	for lv in $res $res$shrink_suffix_old; do
	    local primary
	    for primary in $primary_list; do
		section "EMERGENCY try to restart primary='$primary' resource='$res'"
		local mars_resource_exists="$(remote "$primary" "marsadm view-disk-present $res" | grep '^[0-9]\+$')"
		if (( !mars_resource_exists )); then
		    local vg_name="$(get_vg "$primary")"
		    (remote "$primary" "if ! [[ -e /dev/mars/$lv ]]; then marsadm create-resource --force $res /dev/$vg_name/$lv; fi")
		    sleep 3
		fi
		if (failure_restart_vm "$primary" "" "$res"); then
		    return
		fi
	    done
	done
    else
	failure_restart_vm "$primary_list" "$hyper" "$res"
    fi
    fail "cannot rebuild mars resource='$res' at primary_list='$primary_list'"
}

######################################################################

# LV cleanup over the whole pool (may take some time)

function lv_remove
{
    local host="$1"
    local path="$2"
    local fail_ignore="${3:-0}"

    if exists_hook lv_remove; then
	call_hook lv_remove "$host" "$path" $fail_ignore
    else
	remote "$host" "lvremove $lvremove_opt $path" $fail_ignore
    fi
}

function LV_cleanup
{
    local primary="$1"
    local lv_name="$2"
    local do_it="${3:-0}"

    local total_count=0
    local remove_count=0
    section "Determine hosts and LVs for cleanup"

    local to_check="$(remote "$primary" "marsadm view-cluster-members")"
    echo "Determined the following cluster members: " $to_check >> /dev/stderr

    section "Run over the host list for cleanup"

    echo "do_remove:host:LV_path"
    local host
    for host in $to_check; do
	local path
	for path in $(remote "$host" "ls /dev/*/$lv_name*" 2>/dev/null | grep -v "/mars/" ); do
	    local do_remove=0
	    local disk="$(remote "$host" "marsadm view-get-disk $lv_name")" 2>/dev/null
	    if [[ "$disk" = "" ]]; then
		do_remove=1
		(( remove_count++ ))
	    fi
	    echo "$do_remove:$host:$path"
	    (( total_count++ ))
	    if (( do_remove && do_it )); then
		call_hook disconnect "$host" "$lv_name"
		lv_remove "$host" "$path"
	    fi
	done
    done
    echo "---------------"
    echo "Total number of LVs:    $total_count"
    echo "Total number to remove: $remove_count"
    if (( !do_it && !total )); then
	echo "Nothing to do. Exiting."
	exit 0
    fi
}

######################################################################

# checks for LV migration

function check_migration
{
    # works on global parameters
    [[ "$target_primary" = "" ]] && fail "target hostname is not defined"
    [[ "$target_primary" = "$primary" ]] && fail "target host '$target_primary' needs to be distinct from source host"
    for host in $target_primary $target_secondary; do
	ping $ping_opts "$host" > /dev/null || fail "Host '$host' is not pingable"
	remote "$host" "mountpoint /mars > /dev/null"
	remote "$host" "[[ -d /mars/ips/ ]]"
    done
    call_hook check_host "$primary $secondary_list $target_primary $target_secondary"
    # Check for locks
    if (( $(call_hook resource_locked "$res") )); then
	fail "Resource '$res' is locked at moment => retry later"
    fi
}

function check_vg_space
{
    local host="$1"
    local min_size="$2"

    [[ "$host" = "" ]] && return

    local vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
    local rest="$(remote "$host" "vgs --noheadings -o \"vg_free\" --units k $vg_name" | sed 's/\.[0-9]\+//' | sed 's/k//')" || fail "cannot determine VG rest space"
    echo "$vg_name REST space on '$host' : $rest"
    if (( rest <= min_size )); then
	fail "NOT ENOUGH SPACE on $host (needed: $min_size)"
    fi
}

######################################################################

# actions for LV migration

function get_stripe_extra
{
    # compute LVM stripe number
    local stripes="$(remote "$host" "vgs" | grep '$vg_name ' | awk '{ print $2; }')"
    local extra=""
    if (( stripes > 1 )); then
	echo "Using $stripes LVM stripes" >> /dev/stderr
	extra="-i $stripes"
    fi
    echo "$extra"
}

function create_migration_space
{
    local host="$1"
    local lv_name="$2"
    local size="$3"

    # some checks
    [[ "$host" = "" ]] && return
    local vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
    if (( reuse_lv )); then
	local dev="/dev/$vg_name/${lv_name}"
	if [[ "$(remote "$host" "if [[ -e \"$dev\" ]]; then echo \"EXIST\"; fi")" = "EXIST" ]]; then
	    echo "Device $dev already exists on $host"
	    return
	fi
    else
	remote "$host" "if [[ -e /dev/$vg_name/${lv_name} ]]; then echo \"REFUSING to overwrite /dev/$vg_name/${lv_name} on $host - Do this by hand\"; exit -1; fi"
    fi
    local extra="$(get_stripe_extra "$host" "$vg_name")"

    # do it
    remote "$host" "lvcreate -L ${size}k $etxra -n $lv_name $vg_name"
    injection_point
    sleep 1
}

function merge_cluster
{
    local source_primary="$1"
    local lv_name="$2"
    local target_primary="$3"
    local target_secondary="$4"

    section "Ensure that \"marsadm merge-cluster\" has been executed."

    # This is idempotent.
    if exists_hook merge_cluster; then
	call_hook merge_cluster "$source_primary" "$target_primary"
	call_hook merge_cluster "$source_primary" "$target_secondary"
    else
	remote "$target_primary" "marsadm $(call_hook ssh_port "$host" 1) merge-cluster $source_primary"
	remote "$target_secondary" "marsadm $(call_hook ssh_port "$host" 1) merge-cluster $source_primary"
    fi

    remote "$target_primary" "marsadm wait-cluster"

}

function migration_prepare
{
    local source_primary="$1"
    local lv_name="$2"
    local target_primary="$3"
    local target_secondary="$4"

    merge_cluster "$@"

    section "Idempotence: check whether the additional replica has been alread created"

    local already_present="$(remote "$host" "marsadm view-disk-present $lv_name" | grep '^[0-9]\+$')"
    if (( already_present )); then
	echo "Nothing to do: resource '$lv_name' is already present at '$target_primary'"
	return
    fi

    section "Re-determine and check all resource sizes for safety"

    local size="$(( $(remote "$source_primary" "marsadm view-sync-size $lv_name") / 1024 ))" ||\
	fail "cannot determine resource size"
    local needed_size="$size"
    if [[ "$operation" = "migrate+shrink" ]]; then
	determine_space
	(( needed_size += target_space ))
	echo "Combined migrate+shrink needs $size + $target_space = $needed_size"
    fi

    check_vg_space "$target_primary" "$needed_size"
    check_vg_space "$target_secondary" "$needed_size"

    local primary_vg_name="$(get_vg "$target_primary")"
    local secondary_vg_name="$(get_vg "$target_secondary")"
    local primary_dev="/dev/$primary_vg_name/${lv_name}"
    local secondary_dev="/dev/$secondary_vg_name/${lv_name}"

    section "Create migration spaces"

    create_migration_space "$target_primary" "$lv_name" "$size"
    create_migration_space "$target_secondary" "$lv_name" "$size"

    section "Join the resources"

    if exists_hook join_resource; then
	call_hook join_resource "$source_primary" "$target_primary" "$lv_name" "$primary_dev"
	injection_point
	call_hook join_resource "$source_primary" "$target_secondary" "$lv_name" "$secondary_dev"
	injection_point
    else
	remote "$target_primary" "marsadm $(call_hook ssh_port "$target_primary" 1) join-resource $lv_name $primary_dev"
	injection_point
	remote "$target_secondary" "marsadm $(call_hook ssh_port "$target_secondary" 1) join-resource $lv_name $secondary_dev"
	injection_point
    fi
    remote "$target_primary" "marsadm wait-cluster"
}

function wait_resource_uptodate
{
    local host_list="$1"
    local res="$2"

    section "Wait for MARS UpToDate"

    local host
    for host in $host_list; do
	remote "$host" "marsadm wait-cluster"
    done
    (( verbose )) && echo "$(date) sync rests for '$host_list':"
    local max_wait=15
    while true; do
	(( verbose )) && echo -n "$(date) sync rests:"
	local syncing=0
	local total_rest=0
	for host in $host_list; do
	    local rest="$(verbose=0 remote "$host" "marsadm view-sync-rest $res")"
	    if (( verbose )); then
		if (( rest < 1024 )); then
		    echo -n " $(( rest ))B"
		elif (( rest < 1024 * 1024 )); then
		    echo -n " $(( rest / 1024 ))KiB"
		elif (( rest < 1024 * 1024 * 1024 )); then
		    echo -n " $(( rest / 1024 / 1024 ))MiB"
		else
		    echo -n " $(( rest / 1024 / 1024 / 1024 ))GiB"
		fi
	    fi
	    if (( rest > 0 )); then
		(( syncing++ ))
	    else
		local status="$(verbose=0 remote "$host" "marsadm view-diskstate $res")"
		(( verbose )) && echo -n "/$status"
		if ! [[ "$status" =~ UpToDate ]]; then
		    (( syncing++ ))
		fi
	    fi
	    (( total_rest += rest ))
	done
	(( verbose )) && echo ""
	(( !syncing )) && break
	if (( total_rest > 0 )); then
	    sleep 60
	else
	    (( max_wait-- < 0 )) && break
	    sleep 1
	fi
    done
    (( verbose )) && echo "$(date) sync appears to have finished at '$host_list'"
}

function migrate_resource
{
    local source_primary="$1"
    local target_primary="$2"
    local target_secondary="$3"
    local res="$4"

    wait_resource_uptodate "$target_primary" "$res"

    # critical path
    section "Stopping old primary"

    wait_for_screener "$res" "migrate" "waiting" "$res $source_primary => $target_primary"

    call_hook want_downtime "$res" 1

    failure_handler=failure_restart_vm
    failure_restart_primary="$source_primary $secondary_list"
    failure_restart_hyper=""
    failure_restart_vm="$res"

    call_hook report_downtime "$res" 1
    call_hook resource_stop "$source_primary" "$res"
    injection_point

    section "Migrate cluster config"

    call_hook invalidate_caches

    failure_restart_primary="$source_primary $target_primary $secondary_list $target_secondary"

    call_hook migrate_cm3_config "$source_primary" "$target_primary" "$res"

    failure_restart_primary="$target_primary $source_primary $target_secondary $secondary_list"
    injection_point

    section "Starting new primary"

    call_hook resource_start "$target_primary" "$res"
    injection_point

    section "Checking new primary"

    call_hook resource_check "$res"
    failure_handler=""
    call_hook report_downtime "$res" 0
    call_hook want_downtime "$res" 0
}

function migrate_cleanup
{
    local host_list="$1"
    local host_list2="$(echo $2)"
    local res="$3"

    section "Cleanup migration data at $host_list"

    local new_host_list=""
    local host
    for host in $host_list; do
	# safety: don't kill any targets
	if [[ "$host_list2" != "" ]] && [[ "$host" =~ ${host_list2/ /|/} ]]; then
	    echo "Skipping target $host"
	    continue
	fi
	new_host_list+=" $host"
    done
    leave_resource "$res" "$new_host_list"
    injection_point
    for host in $host_list; do
	echo "CLEANUP LVs $host"
	local vg_name="$(get_vg "$host")"
	if [[ "$vg_name" != "" ]]; then
	    lv_remove "$host" "/dev/$vg_name/$res$tmp_suffix" 1
	    lv_remove "$host" "/dev/$vg_name/$res-copy" 1
	    lv_remove "$host" "/dev/$vg_name/$res$shrink_suffix_old" 1
	fi
    done
    for host in $new_host_list; do
	echo "CLEANUP LVs $host"
	local vg_name="$(get_vg "$host")"
	if [[ "$vg_name" != "" ]]; then
	    lv_remove "$host" "/dev/$vg_name/$res" 1
	    sleep 3
	fi
    done

    section "Recompute host list"

    local new_host_list="$(echo $(
	for host in $host_list $host_list2; do
	    echo "$host"
	    remote "$host" "marsadm lowlevel-ls-host-ips" 2>/dev/null
	done |\
	    awk '{ print $1; }' |\
	    sort -u ))"
    echo "Augmented host list: $new_host_list"
    host_list="$new_host_list"

    for host in $host_list; do
	remote "$host" "marsadm wait-cluster || echo IGNORE cleanup"
    done

    section "Split cluster at $host_list"

    sleep 10
    call_hook prepare_hosts "$host_list"
    call_hook split_cluster "$host_list"
    call_hook finish_hosts "$host_list"
}

######################################################################

# checks for FS shrinking

function determine_space
{
    local src_hyper="${1:-$hyper}"
    local src_primary="${2:-$primary}"
    local dst_primary="${3:-${target_primary:-$2}}"

    declare -g target_space
    declare -g total_space
    if (( target_space > 0 || total_space > 0 )); then
	# already computed
	return
    fi

    lv_path="$(remote "$src_primary" "lvs --noheadings --separator ':' -o \"vg_name,lv_name\"" |\
       grep ":$res$" | sed 's/ //g' |\
       awk -F':' '{ printf("/dev/%s/%s", $1, $2); }')" ||\
	fail "cannot determine lv_path"

    vg_name="$(echo "$lv_path" | cut -d/ -f3)" || fail "cannot determine vg_name"

    echo "Determined the following VG name: \"$vg_name\""
    echo "Determined the following LV path: \"$lv_path\""

    # Assumption: device pathnames should be _uniform_ everywhere.
    local dev="/dev/$vg_name/$lv_name"
    remote "$dst_primary" "if [[ -e ${dev}$shrink_suffix_old ]]; then echo \"REFUSING to overwrite ${dev}$shrink_suffix_old on $src_primary - First remove it - Do this by hand\"; exit -1; fi"

    df="$(remote "$src_hyper" "df $mnt" | grep "/dev/")" || fail "cannot determine df data"
    local used_space="$(echo "$df" | awk '{print $3;}')"
    declare -g total_space="$(echo "$df" | awk '{print $2;}')"
    # absolute or relative space computation
    case "$target_percent" in
    *k)
	target_space="${target_percent%k}"
	;;
    *m)
	target_space="$(( ${target_percent%m} * 1024 ))"
	;;
    *g)
	target_space="$(( ${target_percent%g} * 1024 * 1024 ))"
	;;
    [0-9]*)
	target_space="${target_space:-$(( used_space * 100 / target_percent + 1 ))}" || fail "cannot compute target_space"
	;;
    *)
	fail "illegal syntax \$target_percent='$target_percent'"
	;;
    esac
    (( target_space < min_space )) && target_space=$min_space

    echo "Determined USED  filesystem space at $src_hyper: $used_space"
    echo "Determined TOTAL filesystem space at $src_hyper: $total_space"
    echo "Computed TARGET  filesystem space at $dst_primary: $target_space"
}

function check_shrinking
{
    # works on global variables
    determine_space
    if (( target_space >= total_space )); then
	echo "No need for shrinking the LV space of $res"
	(( !force )) && exit 0
    fi
    for host in $src_primary $secondary_list; do
	check_vg_space "$host" "$target_space"
    done
}

function check_extending
{
    # works on global variables
    determine_space
    if (( target_space <= total_space )); then
	echo "No need for extending the LV space of $res"
	(( !force )) && exit 0
    fi
    delta_space="$(( target_space - total_space + 1024 ))"
    echo "Computed DELTA   space: $delta_space"
    for host in $primary $secondary_list; do
	check_vg_space "$host" "$delta_space"
    done
}

######################################################################

# actions for FS shrinking

## optimize_dentry_cache
# Don't umount the temporary shrink space unnecessarily.
# Try to shutdown the VM / container without umounting.
# Important for high speed.
optimize_dentry_cache="${optimize_dentry_cache:-1}"

## mkfs_cmd
# Tunable for creation of new filesystems.
mkfs_cmd="${mkfs_cmd:-mkfs.xfs -s size=4096 -d agcount=1024}"

## mount_opts
# Options for temporary mounts.
# Not used for ordinary clustermanager operations.
mount_opts="${mount_opts:--o rw,nosuid,noatime,attr2,inode64,usrquota}"

## reuse_mount
# Assume that already existing temporary mounts are the correct ones.
# This will speed up interrupted and repeated runs by factors.
reuse_mount="${reuse_mount:-1}"

## reuse_lv
# Assume that temporary LVs are reusable.
reuse_lv="${reuse_lv:-1}"

## do_quota
# Transfer xfs quota information.
# 0 = off
# 1 = global xfs quota transfer
# 2 = additionally local one
do_quota="${do_quota:-2}"

## xfs_dump_dir
# Temporary space for keeping xfs quota dumps.
xfs_dump_dir="${xfs_dump_dir:-xfs-quota-$start_stamp}"

## xfs_quota_enable
# Command for re-enabling the quota system after shrink.
xfs_quota_enable="${xfs_quota_enable:-xfs_quota -x -c enable}"

## xfs_dump and xfs_restore
# Commands for transfer of xfs quota information.
xfs_dump="${xfs_dump:-xfs_quota -x -c dump}"
xfs_restore="${xfs_restore:-xfs_quota -x -c restore}"

function transfer_quota
{
    local hyper="$1"
    local lv_name="$2"
    local mnt1="$3" # needs to be already mounted
    local mnt2="$4" # needs to be already mounted

    (( !do_quota )) && return

    section "Checks for xfs quota transfer"

    remote "$hyper" "mountpoint $mnt1 && mountpoint $mnt2"

    section "Transfer xfs quota"

    mkdir -p "$xfs_dump_dir"
    local dumpfile="$xfs_dump_dir/xfs_dump.global.$hyper.$lv_name"

    # enable quota
    remote "$hyper" "$xfs_quota_enable $m2"

    # transfer quota
    remote "$hyper" "$xfs_dump $mnt1" > $dumpfile
    ls -l $dumpfile
    wc -l $dumpfile
    if [[ -s $dumpfile ]]; then
	local dev_name="$(remote "$hyper" "df $mnt2" | grep /dev/ | awk '{ print $1; }')"
	echo "dev_name=$dev_name"
	{
	    echo "fs = $dev_name"
	    tail -n +2 < $dumpfile
	} > $dumpfile.new
	remote "$hyper" "$xfs_restore $mnt2" < $dumpfile.new
    else
	echo "QUOTA IS EMPTY"
    fi
}

function create_shrink_space
{
    local host="$1"
    local lv_name="$2"
    local size="$3"

    # some checks
    section "Checking shrink space on $host"

    local vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
    remote "$host" "if [[ -e /dev/$vg_name/${lv_name}$shrink_suffix_old ]]; then echo \"REFUSING to overwrite /dev/$vg_name/${lv_name}$shrink_suffix_old on $host - Do this by hand\"; exit -1; fi"
    if (( reuse_lv )); then
	# check whether LV already exists
	if remote "$host" "[[ -e /dev/$vg_name/${lv_name}$tmp_suffix ]]" 1; then
	    echo "reusing already exists LV /dev/$vg_name/${lv_name}$tmp_suffix on '$host'"
	    return
	fi
    fi
    call_hook disconnect "$host" "$lv_name"
    remote "$host" "if [[ -e /dev/$vg_name/${lv_name}$tmp_suffix ]]; then lvremove $lvremove_opt /dev/$vg_name/${lv_name}$tmp_suffix; fi"
    injection_point

    # do it
    section "Creating shrink space on $host"

    local extra="$(get_stripe_extra "$host" "$vg_name")"
    remote "$host" "lvcreate -L ${size}k $extra -n ${lv_name}$tmp_suffix $vg_name"
    sleep 1
    remote "$host" "$mkfs_cmd /dev/$vg_name/${lv_name}$tmp_suffix"
    injection_point
}

function create_shrink_space_all
{
    local host_list="$1"
    local lv_name="$2"
    local size="$3"

    local host
    for host in $host_list; do
	create_shrink_space "$host" "$lv_name" "$size" "$count"
    done
}

# convention: add a suffix -tmp to the device and mountpoint names each

function make_tmp_mount
{
    local hyper="$1"
    local store="$2"
    local lv_name="$3"
    local suffix="${4:-$tmp_suffix}"

    local mnt="$(call_hook get_mountpoint "$lv_name")"
    if (( reuse_mount )); then
	section "Checking mount $mnt$suffix at $hyper"
	if remote "$hyper" "mountpoint $mnt$suffix" 1; then
	    echo "Reusing already existing mount $mnt$suffix on $hyper"
	    return
	fi
    fi

    section "Creating mount $mnt$suffix at $hyper"

    local vg_name="$(get_vg "$store")" || fail "cannot determine VG for host '$store'"
    local dev_tmp="/dev/$vg_name/$lv_name$suffix"
    if [[ "$store" != "$hyper" ]]; then
	# create remote devices instead
	local old_dev="$dev_tmp"
	dev_tmp="$(call_hook connect "$store" "$hyper" "$lv_name$suffix" 2>&1 | tee -a /dev/stderr | grep "^NEW_DEV" | cut -d: -f2)"
	echo "using tmp dev '$dev_tmp'"
	[[ "$dev_tmp" = "" ]] && fail "cannot setup remote device between hosts '$store' => '$hyper'"
    fi
    remote "$hyper" "mkdir -p $mnt$suffix"
    remote "$hyper" "mount $mount_opts $dev_tmp $mnt$suffix"
    injection_point
}

function make_tmp_umount
{
    local hyper="$1"
    local store="$2"
    local lv_name="$3"
    local suffix="${4:-$tmp_suffix}"

    section "Removing temporary mount from $hyper"

    remote "$hyper" "if mountpoint $mnt$suffix/; then sync; umount $mnt$suffix/ || umount -f $mnt$suffix/; fi"
    injection_point

    if [[ "$store" != "$hyper" ]]; then
	sleep 1
	call_hook disconnect "$store" "$lv_name$suffix"
    fi
}

function copy_data
{
    local hyper="$1"
    local lv_name="$2"
    local suffix="${3:-$tmp_suffix}"
    local nice="${4:-$rsync_nice}"
    local add_opt="${5:-$rsync_opt_prepare}"
    local repeat_count="${6:-$rsync_repeat_prepare}"

    local time_cmd="/usr/bin/time -f 'rss=%M elapsed=%e'"

    section "COPY DATA via rsync"

    local mnt="$(call_hook get_mountpoint "$lv_name")"

    remote "$hyper" "for i in {1..$repeat_count}; do echo round=\$i; $nice $time_cmd rsync $rsync_opt $add_opt $mnt/ $mnt$suffix/; rc=\$?; echo rc=\$rc; if (( !rc || rc == 24 )); then exit 0; fi; echo RESTARTING \$(date); done; echo FAIL; exit -1"
    injection_point
    transfer_quota "$hyper" "$lv_name" "$mnt" "$mnt$suffix"
    remote "$hyper" "sync"
}

function hot_phase
{
    local hyper="$1"
    local primary="$2"
    local secondary_list="$3"
    local lv_name="$4"
    local suffix="${5:-$tmp_suffix}"

    local mnt="$(call_hook get_mountpoint "$lv_name")"
    local vg_name="$(get_vg "$primary")" || fail "cannot determine VG for host '$host'"
    local dev="/dev/$vg_name/$lv_name"
    local dev_tmp="$dev$suffix"
    local mars_dev="/dev/mars/$lv_name"

    # some checks
    section "Checking some preconditions"

    remote "$primary" "if ! [[ -e $dev_tmp ]]; then echo \"Cannot start hot phase: $dev_tmp is missing. Run 'prepare' first!\"; exit -1; fi"
    local host
    for host in $primary $secondary_list; do
	vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
	remote "$host" "blkid /dev/$vg_name/$lv_name || true"
	remote "$host" "blkid /dev/$vg_name/$lv_name$suffix || true"
    done

    # additional temporary mount
    make_tmp_mount "$hyper" "$primary" "$lv_name" "$suffix"

    section "Last online incremental rsync"

    copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_prepare" "$rsync_repeat_prepare"
    # repeat for better dentry caching
    copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_prepare" "$rsync_repeat_prepare"

    call_hook save_local_quota "$hyper" "$lv_name"

    # go offline
    section "Go offline"

    # repeat for better dentry caching
    wait_for_screener "$res" "shrink" "waiting" "$hyper $lv_name" "" "$cache_repeat_lapse" \
	copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_prepare" "$rsync_repeat_prepare"

    call_hook want_downtime "$res" 1

    failure_handler=failure_restart_vm
    failure_restart_primary="$primary $secondary_list"
    failure_restart_hyper="$hyper"
    failure_restart_vm="$lv_name"

    call_hook report_downtime "$res" 1
    if (( optimize_dentry_cache )) && exists_hook resource_stop_vm ; then
	# retain mountpoints
	call_hook resource_stop_vm "$hyper" "$lv_name"
	injection_point
    else
	optimize_dentry_cache=0
	# stop completely
	call_hook resource_stop "$primary" "$lv_name"
	injection_point

	remote "$primary" "marsadm primary $lv_name"
	if [[ "$primary" != "$hyper" ]]; then
	# create remote devices instead
	    mars_dev="$(call_hook connect "$primary" "$hyper" "$lv_name" 2>&1 | tee -a /dev/stderr | grep "^NEW_DEV" | cut -d: -f2)"
	    echo "using tmp mars dev '$mars_dev'"
	    [[ "$mars_dev" = "" ]] && fail "cannot setup remote mars device between hosts '$primary' => '$hyper'"
	fi
	remote "$hyper" "mount $mount_opts $mars_dev $mnt/"
	injection_point
    fi

    section "Final rsync"

    copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_hot" "$rsync_repeat_hot"

    make_tmp_umount "$hyper" "$primary" "$lv_name" "$suffix"
    remote "$hyper" "rmdir $mnt$suffix || true"
    injection_point

    if (( optimize_dentry_cache )); then
	call_hook resource_stop_rest "$hyper" "$primary" "$lv_name"
	injection_point
    else
	remote "$hyper" "sync; umount $mnt/"
	if [[ "$primary" != "$hyper" ]]; then
	    # remove intermediate remote device
	    sleep 1
	    call_hook disconnect "$primary" "$lv_name"
	    injection_point
	fi
    fi

    remote "$primary" "marsadm wait-umount $lv_name"
    remote "$primary" "marsadm secondary $lv_name"
    injection_point

    local full_list="$(get_full_list "$primary $secondary_list")"

    section "IMPORTANT: destroying the MARS resources at $full_list"
    echo "In case of failure, you can re-establish MARS resources by hand."
    echo ""

    failure_handler=failure_rebuild_mars

    delete_resource "$lv_name" "$full_list"
    injection_point

    # backgound safeguard races between delete-resource and create-resource
    for host in $full_list; do
	remote "$host" "marsadm wait-cluster"
	sleep 1
    done &
    sleep 1

    section "CRITICAL: Renaming LVs and re-creating the MARS resource"
    echo "In case of failure, you need to CHECK the correct version by hand."
    echo ""

    for host in $primary $secondary_list; do
	vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
	remote "$host" "lvrename $vg_name $lv_name ${lv_name}$shrink_suffix_old || echo IGNORE backup creation"
	remote "$host" "lvrename $vg_name $lv_name$suffix $lv_name"
	injection_point
    done

    wait

    remote "$primary" "marsadm create-resource --force $lv_name $dev"
    injection_point
    remote "$primary" "marsadm primary $lv_name"

    section "IMPORTANT: go online again"
    echo "In case of failure, you can re-establish MARS resources by hand."
    echo ""

    call_hook resource_start "$primary" "$lv_name"
    injection_point

    failure_handler=""

    section "Re-create the MARS replicas"

    for host in $secondary_list; do
	vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
	dev="/dev/$vg_name/${lv_name}"
	if exists_hook join_resource; then
	    call_hook join_resource "$primary" "$host" "$lv_name" "$dev"
	else
	    remote "$host" "marsadm $(call_hook ssh_port "$host" 1) join-resource $lv_name $dev"
	fi
	injection_point
    done

    call_hook restore_local_quota "$hyper" "$lv_name"

    section "Checking new container"

    call_hook resource_check "$lv_name"
    call_hook report_downtime "$res" 0
    call_hook want_downtime "$res" 0
}

function cleanup_old_remains
{
    local host_list="$1"
    local lv_name="$2"

    section "Cleanup any old LVs"

    local host
    for host in $host_list; do
	local vg_name="$(get_vg "$host")"
	if [[ "$vg_name" != "" ]]; then
	    make_tmp_umount "$host" "$host" "$lv_name" "$tmp_suffix"
	    section "Removing LVs from $host"
	    lv_remove "$host" "/dev/$vg_name/${lv_name}$tmp_suffix" 1
	    lv_remove "$host" "/dev/$vg_name/${lv_name}$shrink_suffix_old" 1
	else
	    echo "ERROR: cannot determine VG for host $host" >> /dev/stderr
	fi
    done
    injection_point
}

######################################################################

# actions for _online_ FS extension / resizing

## fs_resize_cmd
# Command for online filesystem expansion.
fs_resize_cmd="${fs_resize_cmd:-xfs_growfs -d}"

function extend_fs
{
    local hyper="$1"
    local primary="$2"
    local secondary_list="$3"
    local lv_name="$4"
    local size="$5"

    local mnt="$(call_hook get_mountpoint "$res")"

    # extend the LV first
    section "Extend the LV"

    local host
    for host in $primary $secondary_list; do
	local vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
	local dev="/dev/$vg_name/$lv_name"
	remote "$host" "lvresize -L ${size}k $dev"
    done

    section "Extend the MARS resource"

    remote "$primary" "marsadm resize $lv_name"
    injection_point
    sleep 1

    # propagate new size over intermediate iSCSI
    if [[ "$hyper" != "$primary" ]]; then
	section "propagate new size over iSCSI"
	call_hook extend_iscsi "$hyper"
	injection_point
	sleep 3
    fi

    section "Resize the filesystem"

    remote "$hyper" "$fs_resize_cmd $mnt"
    injection_point
}

######################################################################

# internal actions (using global parameters)

### for migration

function migrate_prepare
{
    call_hook prepare_hosts "$primary $secondary_list $target_primary $target_secondary"

    migration_prepare "$primary" "$res" "$target_primary" "$target_secondary"

    call_hook finish_hosts "$primary $secondary_list $target_primary $target_secondary"
}

function migrate_wait
{
    wait_resource_uptodate "$target_primary $target_secondary" "$res"
}

function migrate_check
{
    call_hook check_migrate "$primary" "$target_primary" "$res"
    injection_point
}

function migrate_finish
{
    migrate_resource "$primary" "$target_primary" "$target_secondary" "$res"
    injection_point
}

function manual_migrate_config
{
    call_hook migrate_cm3_config "$primary" "$target_primary" "$res"
}

function migrate_clean
{
    migrate_cleanup "$to_clean_old" "$to_clean_new" "$res"
    injection_point
    cleanup_old_remains "$to_clean_new" "$res"
}

### for shrinking

function shrink_prepare
{
    determine_space
    create_shrink_space_all "$primary $secondary_list" "$res" "$target_space"
    make_tmp_mount "$hyper" "$primary" "$res"
    copy_data "$hyper" "$res" "$tmp_suffix" "$rsync_nice" "$rsync_opt_prepare" "$rsync_repeat_prepare"
    call_hook save_local_quota "$hyper" "$res"
    injection_point
    if (( !reuse_mount )); then
	make_tmp_umount "$hyper" "$primary" "$res"
    fi
}

function shrink_finish
{
    hot_phase "$hyper" "$primary" "$secondary_list" "$res"
}

function shrink_cleanup
{
    cleanup_old_remains "$primary $secondary_list" "$res"
}

### for extending

function extend_stack
{
    determine_space
    extend_fs "$hyper" "$primary" "$secondary_list" "$res" "$target_space"
}

### combined operations

function migrate_plus_shrink
{
    local old_hyper="$hyper"
    local old_primary="$primary"
    local old_secondary="$secondary_list"
    local old_target_secondary="$target_secondary"
    migrate_check
    merge_cluster "$primary" "$res" "$target_primary" "$target_secondary"
    if [[ "$primary" != "$target_primary" ]] && [[ "$primary" != "$target_secondary" ]]; then
	# Less network traffic:
	# Migrate to only one target => new secondary will be created
	# again at shrink 
	target_secondary=""
	migrate_prepare
	migrate_wait
	migrate_finish
	target_secondary="$old_target_secondary"
	declare -g -A hypervisor_host=()
	declare -g -A storage_host=()
	call_hook invalidate_caches
    else
	echo "Skipping the 'migrate' part, continue with 'shrink'"
    fi
    target_hyper="$(get_hyper "$res")" || fail "New hypervisor hostname canot be determined"
    echo "SWAP $old_primary[$old_hyper] $old_secondary => $target_primary[$target_hyper] $target_secondary"
    hyper="$target_hyper"
    primary="$target_primary"
    secondary_list="$target_secondary"
    shrink_prepare
    shrink_finish
    injection_point
    migrate_wait
    if (( wait_before_cleanup )); then
	wait_for_screener "$res" "cleanup" "delayed" "migrate+shrink $res $old_primary => $target_primary" "$wait_before_cleanup"
    fi
    migrate_cleanup "$old_primary $old_secondary" "$target_primary $target_secondary" "$res"
    cleanup_old_remains "$old_primary $old_secondary $target_primary $target_secondary" "$res"
}

### global actions

function lv_clean
{
    LV_cleanup "$primary" "$res" 1
}

######################################################################

# MAIN: get and check parameters, determine hosts and resources, run actions

commands_installed "$commands_needed"

scan_args "$@"

ssh-add -l || fail "You must use ssh-agent and ssh-add with the proper SSH identities"

if (( screener )); then
    [[ "$res" = "" ]] && fail "cannot start screener on empty resource"
    # disallow endless recursion
    export screener=0
    export title="$operation"
    shopt -s extglob
    exec $(dirname "$0")/screener.sh start "${res:-$1}" "$0" "${*//--screener?(=*)/}" --confirm=0
fi

mkdir -p "$football_logdir"

{
echo "$0 $@"

git describe --tags

# special (manual) operations
case "${operation//-/_}" in
manual_config_update)
  call_hook update_cm3_config "$host"
  exit $?
  ;;
esac

# optional: allow syntax "resource:hypervisor:storage"
if [[ "$res" =~ : ]]; then
    rest="${res#*:}"
    res="${res%%:*}"
    if [[ "$rest" =~ : ]]; then
	storage_host[$res]="${rest#*:}"
	rest="${rest%:*}"
    fi
    hypervisor_host[$res]="${rest%:*}"
fi

if [[ "$res" = "" ]]; then
    helpme
    fail "No resource name parameter given"
fi

hyper="$(get_hyper "$res")" || fail "No current hypervisor hostname can be determined"

echo "Determined the following CURRENT hypervisor: \"$hyper\""

if exists_hook get_flavour; then
    flavour="$(call_hook get_flavour "$hyper" 2>/dev/null)"
    echo "Determined the following hypervisor FLAVOUR: \"$flavour\""
fi

primary="$(get_store "$res")" || fail "No current primary hostname can be determined"

echo "Determined the following CURRENT primary: \"$primary\""

for host in $hyper $primary; do
    ping $ping_opts "$host" > /dev/null || fail "Host '$host' is not pingable"
done

remote "$primary" "mountpoint /mars"
remote "$primary" "[[ -d /mars/ips/ ]]"
remote "$primary" "marsadm view $res"

if ! [[ "$operation" =~ manual ]]; then
    if (( $(remote "$primary" "marsadm view-is-primary $res") <= 0 )); then
	fail "Resource '$res' on host '$primary' is not in PRIMARY role"
    fi
    mnt="$(call_hook get_mountpoint "$res")"
    if [[ "$mnt" != "" ]]; then
	remote "$hyper" "mountpoint $mnt"
    fi
fi

secondary_list="$(remote "$primary" "marsadm view-resource-members $res" | { grep -v "^$primary$" | grep -v "^$target_primary$"  | grep -v "^$target_secondary$"|| true; })" || fail "cannot determine secondary_list"
secondary_list="$(echo $secondary_list)"

echo "Determined the following secondaries: '$secondary_list'"

for host in $secondary_list; do
    ping $ping_opts "$host" || fail "Host '$host' is not pingable"
    remote "$host" "mountpoint /mars > /dev/null"
    remote "$host" "[[ -d /mars/ips/ ]]"
#    if [[ "$operation" =~ migrate ]] && ! [[ "$operation" =~ finish ]]; then
#	local check
#	for check in $target_primary $target_secondary; do
#	    if [[ "$check" = "$host" ]]; then
#		fail "target '$check' is also a secondary - this cannot work"
#	    fi
#	done
#    fi
done

# check connections (only for migration)
if [[ "$operation" =~ migrate ]] && ! [[ "$operation" =~ cleanup|wait|manual|shrink ]]; then
    check_migration
fi

if [[ "$operation" = migrate_cleanup ]]; then
    to_clean_old="$(call_hook determine_old_replicas "$primary" "$res" 2>&1 | tee -a /dev/stderr | grep "^FOREIGN" | cut -d: -f2)"
    to_clean_new="$(call_hook determine_new_replicas "$primary" "$res" 2>&1 | tee -a /dev/stderr | grep "^FOREIGN" | cut -d: -f2)"
    if [[ "$to_clean_old$to_clean_new" = "" ]]; then
	echo "NOTHING TO DO"
	exit 0
    fi
    echo "-------------"
    echo "Temporary ${res}${tmp_suffix} partitions + LVs will be removed from:"
    echo "$to_clean_new"
    echo "Stray ${res}${shrink_suffix_old} backup partitions + LVs (old versions before shrinking) will be removed from:"
    echo "$to_clean_old"
elif [[ "$operation" = lv_cleanup ]]; then
    LV_cleanup "$primary" "$res" 0
fi

# determine sizes and available space (only for extending / shrinking)
if [[ "$operation" =~ ^(shrink|shrink_prepare|move\+shrink)$ ]]; then
    check_shrinking
elif [[ "$operation" =~ extend ]]; then
    check_extending
fi

# confirmation

if [[ "$target_primary" != "" ]]; then
    echo "Using the following TARGET primary:   \"$target_primary\""
    echo "Using the following TARGET secondary: \"$target_secondary\""
fi

do_confirm

(( verbose < 1 )) && verbose=1

# main: start the internal actions
main_pid="$BASHPID"
echo "START $(date) main_pid=$main_pid"

case "${operation//-/_}" in
migrate_prepare)
  migrate_prepare
  ;;
migrate_wait)
  migrate_wait
  ;;
migrate_finish)
  migrate_check
  migrate_finish
  ;;
migrate)
  migrate_check
  migrate_prepare
  migrate_wait
  migrate_finish
  if (( wait_before_cleanup )); then
      wait_for_screener "$res" "cleanup" "delayed" "$res $primary => $target_primary" "$wait_before_cleanup"
  fi
  migrate_cleanup "$primary $secondary_list" "$target_primary $target_secondary" "$res"
  cleanup_old_remains "$primary $secondary_list" "$res"
  ;;
migrate_cleanup)
  migrate_clean
  ;;

manual_migrate_config)
  migrate_check
  manual_migrate_config
  ;;


shrink_prepare)
  shrink_prepare
  ;;
shrink_finish)
  shrink_finish
  ;;
shrink_cleanup)
  shrink_cleanup
  ;;
shrink)
  shrink_prepare
  shrink_finish
  if (( wait_before_cleanup )); then
      wait_for_screener "$res" "cleanup" "delayed" "shrink $res"  "$wait_before_cleanup"
  fi
  shrink_cleanup
  ;;

extend)
  extend_stack
  ;;

lv_cleanup)
  lv_clean
  ;;

migrate+shrink)
  migrate_plus_shrink
  ;;

*)
  helpme
  fail "Unknown operation '$operation'"
  ;;
esac

echo "DONE $(date)"
} 2>&1 | log "$football_logdir" "logs$args_info.$start_stamp.$LOGNAME.log"
