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
	    fail "shell command '$cmd' is not installed" "$illegal_status"
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

## football_creds
# List of directories where various credential files can be found.
football_creds="${football_creds:-/usr/lib/mars/creds /etc/mars/creds $script_dir/creds $script_dir $HOME/.mars/creds ./creds}"

## trap_signals
# List of signal names which should be trapped.
# Traps are importnatn for housekeeping, e.g. automatic
# removal of locks.
trap_signals="${trap_signals:-SIGINT}"

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
    for dir in $football_creds $football_confs $football_includes; do
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

## football_backup_dir
# In this directory, various backups are created.
# Intended for manual repair.
football_backup_dir="${football_backup_dir:-$football_logdir/backups}"

## screener
# When enabled, delegate execution to the screener.
# Very useful for running Football in masses.
screener="${screener:-1}"

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

## ssh_auth
# Useful for extra -i options.
ssh_auth="${ssh_auth:-}"

## rsync_opt
# The rsync options in general.
# IMPORTANT: some intermediate progress report is absolutely needed,
# because otherwise a false-positive TIMEOUT may be assumed when
# no output is generated for several hours.
rsync_opt="${rsync_opt:- -aH --inplace --info=progress2,STATS}"

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

## rsync_skip_lines
# Number of rsync lines to skip in output (avoid overflow of logfiles).
rsync_skip_lines="${rsync_skip_lines:-1000}"

## use_tar
# Use incremental Gnu tar in place of rsync:
# 0 = don't use tar
# 1 = only use for the first (full) data transfer, then use rsync
# 2 = always use tar
# Experience: tar has better performance on local data than rsync, but
# it tends to produce false-positive failure return codes on online
# filesystems which are altered during tar.
# The combined mode 1 tries to find a good compromise between both
# alternatives.
use_tar="${use_tar:-1}"

## tar_exe
# Use this for activation of patched tar versions, such as the
# 1&1-internal patched spacetools-tar.
tar_exe="${tar_exe:-/bin/tar}"

## tar_options_src and tar_options_dst
# Here you may give different options for both sides of tar invocations
# (source and destination), such as verbosity options etc.
tar_options_src="${tar_options_src:-}"
tar_options_dst="${tar_options_dst:-}"

## tar_is_fixed
# Tell whether your tar version reports false-positive transfer errors,
# or not.
tar_is_fixed="${tar_is_fixed:-0}"

## tar_state_dir
# This directory is used for keeping incremental tar state information.
tar_state_dir="${tar_state_dir:-/var/tmp}"

## buffer_cmd
# Speed up tar by intermediate buffering.
buffer_cmd="${buffer_cmd:-buffer -m 16m -S 1024m || cat}"

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

## interrupted_status
# This is the "magic" exit code indicating a manual interruption
# (e.g. keypress Ctl-c)
interrupted_status="${interrupted_status:-190}"

## illegal_status
# This is the "magic" exit code indicating an illegal command
# (e.g. syntax error, illegal arguments, etc)
illegal_status="${illegal_status:-191}"

## pre_hand or --pre-hand=
# Set this to do an ordinary handover to a new start position
# (in the source cluster) before doing anything else.
# This may be used for handover to a different datacenter,
# in order to minimize cross traffic between datacenters.
pre_hand="${pre_hand:-}"

## post_hand or --post-hand=
# Set this to do an ordinary handover to a final position
# (in the target cluster) after everything has successfully finished.
# This may be used to establish a uniform default running location.
post_hand="${post_hand:-}"

## tmp_suffix
# Only for experts.
tmp_suffix="${tmp_suffix:--tmp}"

## shrink_suffix_old
# Suffix for backup LVs. These are kept for wome time until
# *_cleanup operations will remove them.
shrink_suffix_old="${shrink_suffix_old:--preshrink}"


# some constants

## start_regex
# At which \$operation the hook football_start
# shoule be called
start_regex="${start_regex:-^(migrate_prepare|migrate|migrate+|shrink_prepare|shrink)}"

## finished_regex
# At which \$operation the hook football_finished
# shoule be called
finished_regex="${finished_regex:-^(migrate_finish|migrate|migrate+|shrink_finish|shrink)}"

commands_needed="${commands_needed:-ssh rsync grep sed awk stdbuf sort head tail tee cat ls basename dirname cut ping date mkdir rm wc bc}"

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

  $0 expand          <resource> <percent>
  $0 extend          <resource> <percent>
    Increase mounted filesystem size during operations.

Combined actions:

  $0 migrate+shrink <resource> <target_primary> [<target_secondary>] [<percent>]
     Similar to migrate ; shrink but produces less network traffic.
     Default percent value (when left out) is $target_percent.

  $0 migrate+shrink+back <resource> <tmp_primary> [<percent>]
     Migrate temporarily to <tmp_primary>, then shrink there,
     finally migrate back to old primary and secondaries.
     Default percent value (when left out) is $target_percent.

Actions for (manual) repair in emergency situations:

  $0 manual_handover  <resource> <target_primary>
     This is useful in place of going to the machines and starting
     handover on their command line. You dont need to log in.
     All hooks (e.g. for downtime / reporting / etc) are automatically
     called.
     Notice: it will only work when there is already a replica
     at <target_primary>, and when further constraints such as
     clustermanager constraints will allow it.
     For a full Football game between different clusters, use
     "migrate" instead.

  $0 manual_migrate_config  <resource> <target_primary> [<target_secondary>]
     Transfer only the cluster config, without changing the MARS replicas.
     This does no resource stopping / restarting.
     Useful for reverting a failed migration.

  $0 manual_config_update <hostname>
     Only update the cluster config, without changing anything else.
     Useful for manual repair of failed migration.

  $0 manual_merge_cluster <hostname1> <hostname2>
     Run "marsadm merge-cluster" for the given hosts.
     Hostnames must be from different (former) clusters.

  $0 manual_split_cluster <hostname_list>
     Run "marsadm split-cluster" at the given hosts.
     Useful for fixing failed / asymmetric splits.
     Hint: provide _all_ hostnames which have formerly participated
     in the cluster.

  $0 repair_vm <resource> <primary_candidate_list>
     Try to restart the VM <resource> on one of the given machines.
     Useful during unexpected customer downtime.

  $0 repair_mars <resource> <primary_candidate_list>
     Before restarting the VM like in repair_vm, try to find a local
     LV where a stand-alone MARS resource can be found and built up.
     Use this only when the MARS resources are gone, and when you are
     desperate. Problem: this will likely create a MARS setup which is
     not usable for production, and therefore must be corrected later
     by hand. Use this only during an emergency situation in order to
     get the customers online again, while buying the downsides of this
     command.

  $0 manual_lock   <item> <host_list>
  $0 manual_unlock <item> <host_list>
     Manually lock or unlock an item at all of the given hosts, in
     an atomic fashion. In most cases, use "ALL" for the item.

Only for testing / development (no stable interfaces):

  $0 manual_call_hook <name> <args>

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
   if (( verbose )); then
     cat <<EOF
Configuration:

  You can place shell variable definitions for overriding any
  tunables into the following locations:

    football_includes=$football_includes

    football_confs=$football_confs

    football_creds=$football_creds

  Filenames should match the following patterns:

    football-*.preconf    Here you may change paths and enable_* variables.
    football-*.conf       Inteded for main parameters.
    football-*.postconf   For late overrides after sourcing modules.
    football-*.reconf     Modify runtime parameters during waits.

EOF
   fi
   show_vars "$0"
   module_list="$description_list $module_list" call_hook describe_plugin
}

######################################################################

# basic infrastructure

failure_handler=""
recursive_failure=0
exit_status=0

function warn
{
    local txt="$1"
    echo "WARNING: $txt" >> /dev/stderr
    call_hook football_warning "$res" "$txt"
}

## call_finished
# Whether to call the hook football_failed at failures.
call_finished="${call_finished:-1}"

declare -g trap_context=""

function fail
{
    local txt="${1:-Unknown failure}"
    local status="${2:--1}"

    unset exit
    local sig
    for sig in $trap_signals; do
	trap - $sig
    done
    echo "" >> /dev/stderr
    echo "=====================================================" >> /dev/stderr
    if [[ "$trap_context" != "" ]]; then
	txt="TRAP context=$trap_context"
	echo "$txt" >> /dev/stderr
	echo "CALL_CHAIN: ${FUNCNAME[@]}" >> /dev/stderr
	status="$interrupted_status"
    fi
    echo "FAIL pid=$BASHPID status=$status '$txt'" >> /dev/stderr

    if (( recursive_failure )); then
	echo "RECURSIVE_FAILURE (now $status): $txt" >> /dev/stderr
	status="$recursive_failure"
	failure_handler=""
    elif [[ "$BASHPID" != "$main_pid" ]]; then
	echo "SUB_FAILURE (now $status): $txt" >> /dev/stderr
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
	exit_status="$status"
	if (( call_finished )); then
	    (call_hook football_failed "$status" "$0" "$@")
	fi
	# unlock any locks
	lock_hosts
	run_local_cleanup_operations
	echo ""
	echo "EXIT pid=$BASHPID status=$status"
    fi >> /dev/stderr
    unset exit
    set -e
    exit $status
}

for sig in $trap_signals; do
    trap "trap_context=\"$sig INIT\" fail" $sig
done

# override the standard exit function for detection of recursion
function exit
{
    local status="${1:-0}"

    unset exit
    for sig in $trap_signals; do
	trap - $sig
    done
    if (( status || recursive_failure )); then
	fail "exit $status" "$status"
    fi
    if [[ "$BASHPID" = "$main_pid" ]]; then
	exit_status="$status"
	if [[ "${operation//-/_}" =~ $finished_regex ]]; then
	    call_hook 0 football_finished "$status" "$0" "$@"
	fi
	# unlock any locks
	lock_hosts
	run_local_cleanup_operations
    fi >> /dev/stderr
    echo ""
    echo "EXIT pid=$BASHPID status=$status" >> /dev/stderr
    unset exit
    set -e
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

declare -g -A local_cleanup_operations=()

function register_cleanup
{
    local id="$1"
    local cmd="$2"

    local_cleanup_operations[$id]="$cmd"
}

function unregister_cleanup
{
    local id="$1"

    local_cleanup_operations[$id]=""
    unset local_cleanup_operations[$id]
    unset -n local_cleanup_operations[$id]
}

function register_unlink
{
    local path="$1"

    local_cleanup_operations[$path]="rm -f $path"
}

function unregister_unlink
{
    local path="$1"

    unregister_cleanup "$path"
}

function run_local_cleanup_operations
{
    echo "${FUNCNAME[@]}"
    local cmd
    for cmd in "${local_cleanup_operations[@]}"; do
	[[ "$cmd" = "" ]] && continue
	echo "local cleanup operation: '$cmd'"
	($cmd)
	echo "rc=$?"
    done
    declare -g -A local_cleanup_operations=()
}

## lock_break_timeout
# When remote ssh commands are failing, remote locks may sustain forever.
# Avoid deadlocks by breaking remote locks after this timeout has elapsed.
# NOTICE: these type of locks are only intended for short-term locking.
lock_break_timeout="${lock_break_timeout:-3600}" # seconds

declare -g locked_hosts=""
declare -g locked_items=""

function lock_hosts
{
    local do_lock="${1:-0}"
    local host_list="${2:-$locked_hosts}"
    local item_list="${3:-${locked_items:-ALL}}"
    local exclusive="${4:-1}"

    if [[ "$BASHPID" != "$main_pid" ]]; then
	if (( !do_lock )); then
	    return
	fi
	if (( exclusive )); then
	    warn "Don't call $FUNCNAME from a subshell"
	fi
    fi

    # IMPORTANT: sorting of names is necessary for deadlock avoidance
    local host
    local item
    host_list="$(echo -n $(
    for host in $host_list; do
	echo $host
    done | sort -u) )"
    if [[ "$host_list" = "" ]]; then
	return
    fi
    item_list="$(echo -n $(
    for item in $item_list; do
	echo $item
    done | sort -u) )"
    if [[ "$item_list" = "" ]]; then
	echo "IMPLAUSIBLE locking $do_lock: empty item list for host_list='$host_list'"
	return
    fi
    local unlock_cmd=""
    for item in $item_list; do
	unlock_cmd+="rm -f /tmp/LOCK.$item;"
    done
    if (( do_lock )); then
	echo "Locking '$item_list' on hosts '$host_list'"
	# Hint: this implies O_CREAT | O_EXCL
	local lock_cmd="set -o noclobber"
	local check_cmd=""
	for item in $item_list; do
	    if (( exclusive )); then
		lock_cmd+=" && echo $user_name > /tmp/LOCK.$item"
	    else
		lock_cmd+=" && echo $user_name >> /tmp/LOCK.$item"
	    fi
	    check_cmd+="stat --format=%Y /tmp/LOCK.$item;"
	done
	while true; do
	    local obtained=""
	    local failed=0
	    for host in $host_list; do
		remote "$host" "$lock_cmd" 1
		if (( $? )); then
		    (( failed++ ))
		    break
		fi
		obtained+=" $host"
	    done
	    if (( !failed )); then
		echo "LOCKED '$item_list' on hosts '$obtained'"
		break
	    fi
	    # Some already obtained locks need to be reverted...
	    local u_host
	    for u_host in $obtained; do
		remote "$u_host" "$unlock_cmd"
	    done
	    echo "WAITING_FOR_LOCK $(date +%s) $(date): locks '$item_list' currently not obtainable at '$host'"
	    sleep  $(( $RANDOM * 20 / 32767 + 10 ))
	    local max_stamp="$(
	    for host in $host_list; do
		remote "$host" "$check_cmd" 1
	    done | awk '{ if ($1 > s) { s = $1; } } END{ print s; }')"
	    local now="$(date +%s)"
	    if [[ "$max_stamp" != "" ]] &&\
		(( max_stamp )) &&\
		(( max_stamp + lock_break_timeout < now )); then
		echo "max_stamp=$max_stamp"
		echo "now      =$now"
		echo "BREAKING LOCKS '$item_list' on hosts '$host_list'"
		for host in $host_list; do
		    remote "$host" "$unlock_cmd"
		done
	    fi
	done
	locked_hosts="$(for item in $locked_hosts $host_list; do echo $item; done | sort -u)"
	locked_items="$(for item in $locked_items $item_list; do echo $item; done | sort -u)"
    else
	echo "UnLocking '$item_list' on hosts '$host_list'"
	for host in $host_list; do
	    remote "$host" "$unlock_cmd"
	done
	echo "UNLOCKED '$item_list' on hosts '$host_list'"
	locked_hosts=""
	locked_items=""
    fi
    return 0
}

args_info=""

function scan_vars
{
    declare -g -a argv=()
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
	argv[$index]="$par"
	(( index++ ))
    done
    if [[ "$operation" = "help" ]]; then
	helpme
	exit 0
    fi
}

function scan_args
{
    local -a params
    local index=0
    local list=0
    local par
    for par in "$@"; do
	if (( !index )); then
	    if [[ "$par" =~ migrate_cleanup|lv_cleanup ]]; then
		local -a params=(operation res)	
	    elif [[ "$par" =~ migrate ]]; then
		local -a params=(operation res target_primary target_secondary)
	    elif [[ "$par" =~ shrink|extend|expand ]]; then
		local -a params=(operation res target_percent)
	    elif [[ "$par" =~ manual_handover ]]; then
		local -a params=(operation res target_primary)
	    elif [[ "$par" =~ manual_config_update ]]; then
		local -a params=(operation host)
	    elif [[ "$par" =~ manual_|plugin_|generic_ ]]; then
		operation="$par"
		return
	    elif [[ "$par" =~ repair_|test_ ]]; then
		local -a params=(operation res primary secondary_list)
	    elif [[ "$par" =~ tool ]]; then
		operation="$par"
		return
	    else
		local module
		for module in $module_list; do
		    if [[ "$par" =~ ^${module}_ ]]; then
			operation="$par"
			return
		    fi
		done
		helpme
		fail "unknown operation '$1'" "$illegal_status"
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
	    if (( list )); then
		echo "$lhs+=\" $par\""
		eval "$lhs+=\" $par\""
	    else
		echo "$lhs=$par"
		eval "$lhs=$par"
	    fi
	    args_info+=".${par//:/_}"
	    if [[ "$lhs" =~ _list ]]; then
		(( list++ ))
	    else
		(( index++ ))
	    fi
	else
	    helpme
	    fail "stray parameter '$par'" "$illegal_status"
	fi
    done
}

function do_confirm
{
    local skip="$1"
    local response

    if (( !confirm )); then
	return
    fi

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
	ssh $port $ssh_auth $ssh_opt "$login" "$cmd"
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

declare -g phase="starting"

function phase
{
    local name="${1:-DEFAULT}"
    local txt="${2:-}"

    phase="$name"

    echo ""
    echo ""
    echo "============================================================================="
    echo "================== PHASE $name ==============================="
    echo "$name: $txt"
    echo ""

    call_hook phase "$name" "$res" "$txt"
}

section_nr=1

function section
{
    local txt="${1:--}"

    echo ""
    echo "==================================================================="
    echo "${section_nr}. $txt"
    echo ""

    call_hook section "$section_nr" "$res" "$txt"
    (( section_nr++ ))
    return 0
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
	    fail "Cannot determine hypervisor hostname for resource '$res'" "$illegal_status"
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
	    fail "Cannot determine storage hostname for resource '$res'" "$illegal_status"
	if [[ "$store" = "" ]]; then
	    # assume local storage
	    store="$(get_hyper "$res")"
	fi
	storage_host[$res]="$store"
    fi
    [[ "$store" = "" ]] && return -1
    echo "$store"
}

declare -g -A vgs=()

function get_vg
{
    local host="$1"

    [[ "$host" = "" ]] && return -1
    declare -g -A vgs
    local vg="${vgs[$host]}"
    if [[ "$vg" = "" ]]; then
	vg="$(call_hook get_vg "$host")" ||\
	    fail "Cannot determine volume group for host '$host'" "$illegal_status"
	vgs[$host]="$vg"
    fi
    [[ "$vg" = "" ]] && return -1
    echo "$vg"
}

######################################################################

# further helpers

function get_cpu_count
{
    local host="$1"

    local cmd="cat /proc/cpuinfo | grep '^processor' | wc -l"
    local cpu_count="$(remote "$host" "$cmd" 1)"
    echo "$cpu_count"
}

function get_ram_gb
{
    local host="$1"

    local cmd="cat /proc/meminfo | grep '^MemTotal:'| grep -o '[0-9]\+' "
    local ram_kb="$(remote "$host" "$cmd" 1)"
    echo "Host '$host' has '$ram_kb' kiB RAM" >> /dev/stderr
    local ram_gb="$(( ram_kb / 1024 / 1024 ))"
    echo "Host '$host' has '$ram_gb' GiB RAM" >> /dev/stderr
    echo "$ram_gb"
}

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

declare -g -A cluster_members=()

function get_cluster_members
{
    local host="$1"

    local cached="${cluster_members[$host]}"
    if [[ "$cache" = "" ]]; then
	cached="$(remote "$host" "marsadm view-cluster-members" 1)"
	cluster_members[$host]="$cached"
    fi
    echo "$cached"
}

function get_full_list
{
    local host_list="$1"
    local with_hyper="${2:-0}"

    echo "Extending host list '$host_list'" >> /dev/stderr
    local full_list=""
    while true; do
	full_list="$(echo $(for host in $host_list; do echo $host; if (( with_hyper )); then call_hook get_hyper $host; get_store $host; fi; get_cluster_members "$host"; done | sort -u) )"
	[[ "$full_list" = "$host_list" ]] && break
	host_list="$full_list"
    done
    echo "Extended  host list '$full_list'" >> /dev/stderr
    echo $full_list
}

function handover
{
    local target="$1"
    local res="$2"

    local current="$(get_store "$res")"
    if [[ "$current" = "" ]]; then
	fail "cannot determine current store for '$res'" "$illegal_status"
    fi
    if [[ "$current" = "$target" ]]; then
	echo "No handover needed: resource '$res' is already running at '$target'"
	return
    fi
    if [[ "$(remote "$target" "marsadm view-resource-members $res" | grep "^$target$")" != "$target" ]]; then
	warn "Handover to '$target' is not possible: host is not member of resource '$res'"
	return
    fi

    lock_hosts 1 "$current $target" ALL

    call_hook check_handover "$current" "$target" "$res"

    lock_hosts

    section "Handover '$res' $current => $target"

    wait_for_screener "$res" "handover" "waiting" "$res $current => $target"

    wait_for_logfile "$res" "$target"

    call_hook want_downtime "$res" 1

    lock_hosts 1 "$current $target" ALL

    failure_handler=failure_restart_vm
    failure_restart_primary="$current $target $primary $secondary_list $target_primary $target_secondary"
    failure_restart_hyper=""
    failure_restart_vm="$res"
    call_hook resource_stop "$current" "$res"
    injection_point
    call_hook invalidate_caches
    call_hook resource_start "$target" "$res"
    call_hook resource_check "$res" "$current" "$target"
    failure_handler=""

    lock_hosts

    call_hook want_downtime "$res" 0

    local location="$(call_hook get_location "$target" 2>/dev/null)"
    echo "SCREENER_LOCATION=$location"
}

function _leave_resource
{
    local res="$1"
    local host_list="$2"

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
	if (( !count )); then
	    return 0
	fi
	echo "LEFT $count: REPEAT delete-resource $host_list"
	sleep 7
	echo "RETRY $retry leave-resource" 
    done
    fail "leave-resource $res did not work on $host_list"
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

    lock_hosts 1 "$host_list" ALL

    _leave_resource "$res" "$host_list"

    lock_hosts
}

function delete_resource
{
    local res="$1"
    local host_list="$2"

    local full_list="$(get_full_list "$host_list")"

    local retry
    for (( retry=0; retry < 3; retry++ )); do
	local host
	_leave_resource "$res" "$full_list"
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

test_deleted_rounds="${test_deleted_rounds:-100}"

function test_delete_resource
{
    verbose=1
    local retry
    for (( retry = 0; retry < test_deleted_rounds; retry++ )); do
	call_hook resource_stop "$primary" "$res"
	remote "$primary" "marsadm secondary $res"
	remote "$primary" "marsadm view-wait-is-primary-off $res || echo IGNORE"
	delete_resource "$res" "$primary $secondary_list"
	echo "============== $retry"
	sleep 20
	vg_name="$(get_vg "$primary")"
	dev="/dev/$vg_name/$res"
	remote "$primary" "if ! [[ -e /dev/mars/$res ]]; then marsadm create-resource --force $res $dev; fi"
	call_hook resource_start "$primary" "$res"
	for host in $secondary_list; do
	    echo "Secondary: $host"
	    remote "$host" "marsadm wait-cluster"
	    call_hook join_resource "$primary" "$host" "$res" "$dev"
	done
	remote "$primary" "marsadm cron"
	wait_resource_uptodate "$secondary_list" "$res"
	remote "$primary" "marsadm cron"
	echo "============== $retry"
	sleep 10
	remote "$primary" "marsadm cron"
	sleep 20
    done
    echo "TEST DONE"
}

function reconf
{
    source_glob "$football_confs"    "football-*.reconf"  "Reconf" 0
    source_glob "$football_includes" "football-*.reconf"  "Reconf" 0
}

function compute_timeout_after
{
    local res="$1"
    local host_list="$2"
    local timeout="${3:-$wait_timeout}"

    local last_stamp=0
    local host
    for host in $host_list; do
	local cmd="stat --printf='%Y' /mars/resource-$res/data-$host"
	local stamp="$(remote "$host" "$cmd" 1)"
	echo "Host '$host' resource '$res' was created at '$stamp'"
	if (( stamp > last_stamp )); then
	    last_stamp="$stamp"
	fi
    done >> /dev/stderr 2>&1
    local now="$(date +%s)"
    if (( !last_stamp )); then
	echo "Using the full timeout '$timeout'" >> /dev/stderr
	echo "$timeout"
	return
    fi
    local diff=$(( timeout - ( now - last_stamp ) / 60 ))
    echo "Computed rest timeout: '$diff' minutes" >> /dev/stderr
    if (( diff <= 0 )); then
	# Shortest possible wait is 1 minute (0 would disable it completely)
	echo "1"
    else
	echo "$diff"
    fi
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

    reconf
    local enable="enable_${situation}_${mode}"
    if (( !$enable )); then
	echo "$enable is off"
    fi
    echo "$enable is on"

    local hot_round=0
    local lock_round=0
    local total_round=0
    local reset_freq=0
    if (( $enable )); then
	call_hook start_wait "$res" "$mode" "$situation: $msg"
    fi
    while true; do
	# Allow changes of config variables during runtime
	if (( ! ( total_round % 60 ) )); then
	    reconf
	else
	    reconf > /dev/null 2>&1
	fi

	local locked="$(verbose=0 call_hook resource_locked "$res")"
	if (( locked )); then
	    (( lock_round++ ))
	    if (( ! ( total_round % 10 ) )); then
		echo "SCREENER_INFO=locked for $lock_round minutes"
	    fi
	fi
	local poll=0
	if (( $enable )); then
	    poll="$(verbose=0 call_hook poll_wait "$res" "$mode" 0 $reset_freq)"
	fi
	if (( !poll && !locked )); then
	    return
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
	if (( repeat_lapse > 0 && hot_round >= repeat_lapse )); then
	    hot_round=0
	    if [[ "$lapse_cmd" != "" ]]; then
		$lapse_cmd "$@"
	    fi
	    reset_freq=1
	fi
	if (( !locked )); then
	    (( total_round++ ))
	fi
	if (( timeout > 0 && total_round >= timeout )); then
	    echo "TIMEOUT SCREENER_$mode $(date +%s) $(date)"
	    call_hook poll_wait "$res" "$mode" 1 1
	elif (( keypress )); then
	    echo "KEYPRESS SCREENER_$mode $(date +%s) $(date)"
	    call_hook poll_wait "$res" "$mode" 1 1
	    break
	fi
    done
    echo "SCREENER_TIME_LOCKED=$lock_round"
    if [[ "$lapse_cmd" != "" ]]; then
	$lapse_cmd "$@"
    fi
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
	if ping $ping_opts "$res"; then
	    echo "Resource $res is working, no restart needed."
	    return 0
	fi
	if [[ "$primary_list" = "" ]] && [[ "$hyper" != "" ]]; then
	    # Last resort.
	    # Assume that the hypervisor is working and try to work there
	    section "EMERGENCY try to restart hyper='$hyper' resource='$res'"

	    lock_hosts 1 "$hyper" ALL 0

	    # try to get a defined state
	    call_hook 0 resource_stop_vm "$hyper" "$res" || echo IGNORE
	    # try to start twice
	    if ! call_hook 0 resource_start_vm "$hyper" "$res"; then
		call_hook 0 resource_stop_vm "$hyper" "$res" || echo IGNORE
		call_hook resource_start_vm "$hyper" "$res"
	    fi
	    return
	fi

	lock_hosts 1 "$primary_list" ALL 0

	local -A tried=()
	local primary
	for primary in $primary_list; do
	    (( tried[$primary] )) && continue
	    section "EMERGENCY check whether restart primary='$primary' resource='$res' is possible"

	    if [[ "$(call_hook is_startable "$primary" "$res" | tee -a /dev/stderr | tail -1)" != "1" ]]; then
		echo "Startup of $res is reported as not possible at $primary".
		echo "If this is wrong, fix configs by hand."
		lock_hosts 0 "$primary" ALL
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
		    echo "VM '$res' appears to be running"
		    lock_hosts
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
	if ping $ping_opts "$res"; then
	    echo "Resource $res is working, no restart needed."
	    return 0
	fi
	# Assuption: at least some usable LV must exist.
	# Don't try to rename anything. In case of emergency, just use
	# everything which looks plausible.

	local lv
	for lv in $res $res$shrink_suffix_old; do
	    local primary
	    for primary in $primary_list; do
		section "EMERGENCY try to restart primary='$primary' resource='$res'"
		lock_hosts 1 "$primary" ALL 0
		local mars_resource_exists="$(remote "$primary" "marsadm view-disk-present $res" | grep '^[0-9]\+$')"
		echo "Resource '$res' at '$primary' existing=$mars_resource_exists"
		if (( !mars_resource_exists )); then
		    local vg_name="$(get_vg "$primary")"
		    (remote "$primary" "if ! [[ -e /dev/mars/$lv ]]; then marsadm create-resource --force $res /dev/$vg_name/$lv; fi")
		    sleep 3
		fi
		if (failure_restart_vm "$primary" "" "$res"); then
		    return
		fi
		if (( !mars_resource_exists )); then
		    echo "Trying to remove the stray resource '$res' from '$primary'"
		    (_leave_resource "$res" "$primary")
		    sleep 20
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

## startup_when_locked
# When == 0:
#  Don't abort and don't wait when a lock is detected at startup.
# When == 1 and when enable_startup_waiting=1:
#  Wait until the lock is gone.
# When == 2:
#  Abort start of script execution when a lock is detected.
#  Later, when a locks are set _during_ execution, they will
#  be obeyed when enable_*_waiting is set (instead), and will
#  lead to waits instead of aborts.
startup_when_locked="${startup_when_locked:-1}"

function check_locked
{
    if (( $(call_hook resource_locked "$res") )); then
	if (( startup_when_locked <= 0 )); then
	    warn "Resource '$res' is locked at the moment"
	elif (( startup_when_locked == 1 )); then
	    wait_for_screener "$res" startup
	else
	    fail "Resource '$res' is locked at the moment => retry later" "$illegal_status"
	fi
    fi
}

function check_migration
{
    # works on global parameters
    [[ "$target_primary" = "" ]] && fail "target hostname is not defined" "$illegal_status"
    if [[ "$target_primary" = "$primary" ]] ; then
	echo "Nothing to do: source primary '$primary' is equal to the target primary"
    fi
    for host in $target_primary $target_secondary; do
	ping $ping_opts "$host" > /dev/null || fail "Host '$host' is not pingable"
	remote "$host" "mountpoint /mars > /dev/null"
	remote "$host" "[[ -d /mars/ips/ ]]"
    done
    call_hook check_host "$primary $secondary_list $target_primary $target_secondary"
    # Check for locks
    check_locked
}

function check_vg_space
{
    local host="$1"
    local min_size="$2"
    local lv_name="$3"
    local suffix="$4"

    [[ "$host" = "" ]] && return

    local vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'" "$illegal_status"
    local rest="$(remote "$host" "vgs --noheadings -o \"vg_free\" --units k $vg_name" | sed 's/\.[0-9]\+//' | sed 's/k//')" || fail "cannot determine VG rest space"
    echo "$vg_name REST space on '$host' : $rest"
    if [[ "$lv_name" != "" ]]; then
	local dev="/dev/$vg_name/$lv_name$suffix"
	if remote "$host" "[[ -b $dev ]]" 1; then
	    echo "Device $dev already exists at '$host'"
	    return
	fi
	local cmd="lvs | grep '$lv_name$shrink_suffix_old' | wc -l"
	local present="$(remote "$host" "$cmd" 1)"
	echo "Backup LV '$lv_name$shrink_suffix_old' present at host $host: '$present'"
	if (( present )); then
	    echo "Assuming that shrink is already done at '$host'."
	    echo "If you want to start another shrink, first cleanup the old backup LV '$lv_name$shrink_suffix_old'."
	    return
	fi
    fi
    if (( rest <= min_size )); then
	if (( force )); then
	    echo "NOT ENOUGH SPACE on $host (needed: $min_size)"
	else
	    fail "NOT ENOUGH SPACE on $host (needed: $min_size)" "$illegal_status"
	fi
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
    local vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'" "$illegal_status"
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
    local lv_name="$1"
    local host_list="$2"
    local target_list="$3"

    section "Ensure that \"marsadm merge-cluster\" has been executed at '$host_list' => '$target_list'."
    host_list="$(echo $(list_union "$host_list" "$target_list") )"
    echo "New host list '$host_list'"

    local host
    if [[ "$lv_name" != "" ]]; then
	# Safeguard operating errors
	for host in $host_list; do
	    remote "$host" "marsadm up $lv_name" 1
	done
    fi

    local ok=1
    for host in $host_list; do
	local others="$(echo $(remote "$host" "marsadm view-cluster-members" 1) )"
	echo "Host '$host' has partners '$others'"
	local missing="$(echo $(list_minus "$host_list" "$others") )"
	if [[ "$missing" != "" ]]; then
	    echo "On host '$host', partners '$missing' are missing"
	    target_list="$(echo $(list_union "$target_list" "$missing") )"
	    ok=0
	fi
    done
    if (( ok )) && [[ "$lv_name" != "" ]]; then
	echo "No need for merge-cluster '$host_list' => '$target_list'"
	return
    fi
    echo "New target list: '$target_list'"

    declare -g -A cluster_members=()

    call_hook prepare_hosts "$host_list"

    # This is idempotent.
    for host in $target_list; do
	local host2
	for host2 in $host_list; do
	    [[ "$host" = "$host2" ]] && continue
	    if exists_hook merge_cluster; then
		call_hook merge_cluster "$host2" "$host"
	    else
		remote "$host" "marsadm $(call_hook ssh_port "$host" 1) merge-cluster $host2"
	    fi
	done
    done

    call_hook finish_hosts "$host_list"

    for host in $host_list; do
	local ok=1
	local retry=3
	while (( retry-- >= 0 )); do
	    remote "$host" "marsadm wait-cluster"
	    if remote "$host" "marsadm view all" | grep " is dead"; then
		sleep 30
	    else
		ok=1
		break
	    fi
	done
	if (( !ok )); then
	    fail "bad mars connection at '$host', please fix your network / firwalling / etc"
	fi
    done
}

function migration_prepare
{
    local lv_name="$1"
    local source_primary="$2"
    local source_secondary="$3"
    local target_primary="$4"
    local target_secondary="$5"
    local extra_secondary="$6"

    section "Idempotence: check whether the additional replica has been alread created"

    local -A already=()
    local need=0
    local host
    for host in $target_primary $target_secondary; do
	local already_present="$(remote "$host" "marsadm view-disk-present $lv_name" | grep '^[0-9]\+$')"
	if (( already_present )); then
	    echo "Nothing to do at '$host': resource '$lv_name' is already present"
	    already[$host]=1
	else
	    (( need++ ))
	fi
    done
    if (( !need )); then
	echo "All replicas are already created at $target_primary $target_secondary"
	return
    fi

    section "Wait when too many syncs are already running"

    wait_for_syncs "$lv_name" "$target_primary $target_secondary"

    section "Re-determine and check all resource sizes for safety"

    local host_list="$(get_augmented_host_list "$source_primary $source_secondary $target_primary $target_secondary")"

    lock_hosts 1 "$host_list" ALL

    local size="$(( $(remote "$source_primary" "marsadm view-sync-size $lv_name") / 1024 ))" ||\
	fail "cannot determine resource size"
    local needed_size="$size"
    if [[ "$operation" =~ migrate\+shrink ]]; then
	determine_space
	(( needed_size += target_space ))
	echo "Combined migrate+shrink needs $size + $target_space = $needed_size"
    fi

    for host in $target_primary $target_secondary; do
	(( already[$host] )) && continue
	check_vg_space "$host" "$needed_size" "$lv_name"
    done

    merge_cluster "$lv_name" "$host_list" "$target_primary $target_secondary $extra_secondary"

    section "Create migration spaces"

    for host in $target_primary $target_secondary; do
	(( already[$host] )) && continue
	create_migration_space "$host" "$lv_name" "$size"
    done
    injection_point

    section "Join the resources"

    remote "$target_primary" "marsadm wait-cluster"

    call_hook prepare_hosts "$source_primary $target_primary $target_secondary"

    for host in $target_primary $target_secondary; do
	(( already[$host] )) && continue
	cleanup_done[$host]=0
	remote "$host" "marsadm wait-cluster"
	local vg_name="$(get_vg "$host")"
	local dev="/dev/$vg_name/${lv_name}"
	if exists_hook join_resource; then
	    call_hook join_resource "$source_primary" "$host" "$lv_name" "$dev"
	else
	    remote "$host" "marsadm $(call_hook ssh_port "$host" 1) join-resource $lv_name $dev"
	fi
	injection_point
    done
    remove_intent "$football_logdir/intent.syncs.$lv_name" >> /dev/stderr

    call_hook finish_hosts "$source_primary $target_primary $target_secondary"

    lock_hosts

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
    local percent=-1
    local size="$(verbose=0 remote "$host" "marsadm view-resource-size $res")"
    if (( verbose )); then
	echo "Resource '$res' size: '$size'"
	echo "SCREENER_INFO="
	echo "$(date) sync rests for '$host_list':"
    fi
    local max_wait=15
    while true; do
	local min_percent=101
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
	    if (( size > 0 )); then
		local this_percent=$(( ( size - rest ) * 100 / size ))
		if (( this_percent < min_percent )); then
		    min_percent=$this_percent
		fi
	    fi
	done
	if (( verbose )); then
	    echo ""
	    if (( min_percent != percent && min_percent <= 100 )); then
		echo "SCREENER_INFO=$min_percent%"
		percent=$min_percent
	    fi
	fi
	(( !syncing )) && break
	if (( total_rest > 0 )); then
	    sleep 60
	else
	    (( max_wait-- < 0 )) && break
	    sleep 1
	fi
    done
    if (( verbose )); then
	echo "SCREENER_INFO="
	echo "$(date) sync appears to have finished at '$host_list'"
    fi
}

## resource_pre_check
# Useful for debugging of container problems.
# Normally not needed.
resource_pre_check="${resource_pre_check:-0}"

function migrate_resource
{
    local source_primary="$1"
    local source_secondary="$2"
    local target_primary="$3"
    local target_secondary="$4"
    local res="$5"

    if [[ "$source_primary" = "$target_primary" ]]; then
	echo "Nothing to do: source primary '$source_primary' is equal to the target primary"
	return
    fi

    wait_resource_uptodate "$target_primary" "$res"

    if (( resource_pre_check )); then
	call_hook resource_check "$res" "$source_primary" "$target_primary"
    fi

    # critical path
    section "Stopping old primary"

    wait_for_screener "$res" "migrate" "waiting" "$res $source_primary => $target_primary"

    wait_for_logfile "$res" "$target_primary"

    call_hook want_downtime "$res" 1
    call_hook tell_action migrate finish
    call_hook update_ticket migrate_finish running

    local full_list="$(get_full_list "$source_primary $target_primary $target_secondary")"
    lock_hosts 1 "$full_list" ALL

    failure_handler=failure_restart_vm
    failure_restart_primary="$source_primary $secondary_list"
    failure_restart_hyper=""
    failure_restart_vm="$res"

    call_hook report_downtime "$res" 1
    call_hook resource_stop "$source_primary" "$res"
    injection_point

    # Safeguard against some "byzantinian errors" ...
    local host
    for host in $source_secondary; do
	echo "Stopping also '$host' for safety"
	if ! (call_hook resource_stop "$host" "$res"); then
	    echo "Stop rc=$?, continuing anyway"
	fi
    done

    section "Migrate cluster config"

    call_hook invalidate_caches

    failure_restart_primary="$source_primary $target_primary $secondary_list $target_secondary"

    call_hook migrate_cm3_config "$source_primary" "$target_primary" "$res"

    failure_restart_primary="$target_primary $source_primary $target_secondary $secondary_list"
    injection_point

    section "Starting new primary"

    call_hook resource_start "$target_primary" "$res"
    injection_point

    lock_hosts

    section "Checking new primary"

    call_hook resource_check "$res" "$source_primary" "$target_primary"
    failure_handler=""
    call_hook report_downtime "$res" 0
    call_hook want_downtime "$res" 0
    call_hook update_ticket migrate_finish finished
}

function get_augmented_host_list
{
    local host_list="$1"

    local host
    echo $(
	for host in $host_list; do
	    echo "$host"
	    remote "$host" "marsadm lowlevel-ls-host-ips" 2>/dev/null
	done |\
	    awk '{ print $1; }' |\
	    sort -u
    )
}

function manual_merge_cluster
{
    local host1="$1"
    local host2="$2"

    local host_list="$(get_augmented_host_list "$host1 $host2")"
    echo "Augmented host list: $host_list"

    lock_hosts 1 "$host_list" ALL

    call_hook prepare_hosts "$host_list"
    merge_cluster "$lv_name" "$host_list" "$host1 $host2"
    call_hook finish_hosts "$host_list"

    lock_hosts
}

function _split_cluster
{
    local host_list="$1"

    local host_list="$(get_augmented_host_list "$host_list")"
    echo "Augmented host list: $host_list"

    lock_hosts 1 "$host_list" ALL

    call_hook prepare_hosts "$host_list"
    call_hook split_cluster "$host_list"
    call_hook finish_hosts "$host_list"

    lock_hosts
}

declare -g -A cleanup_done=()
declare -g cleanup_asked=0

function migrate_cleanup
{
    local host_list="$1"
    local host_list2="$(echo $2)"
    local res="$3"
    local do_split="${4:-1}"
    local situation="${5:-cleanup}"

    phase migrate_cleanup

    section "Check for cleanup at '$host_list' excluding '$host_list2'"

    local new_host_list=""
    local host
    for host in $host_list; do
	# safety: don't kill any targets
	if [[ "$host_list2" != "" ]] && [[ "$host" =~ ${host_list2/ /|/} ]]; then
	    echo "Skipping target $host"
	    continue
	fi
	# Skip when already left
	if (( cleanup_done[$host] )); then
	    echo "Skipping already done '$host'"
	    continue
	fi
	local vg_name="$(get_vg "$host")"
	if ! remote "$host" "[[ -e /dev/$vg_name/$res ]] || [[ -e /dev/$vg_name/$res$tmp_suffix ]] || [[ -e /dev/$vg_name/$res$shrink_suffix_old ]]" 1; then
	    echo "Skipping already pruned '$host'"
	    cleanup_done[$host]=1
	    continue
	fi
	echo "Host '$host' needs cleanup"
	new_host_list+=" $host"
    done
    if [[ "$new_host_list" = "" ]]; then
	echo "All are already left from '$host_list'"
	return
    fi
    echo "new_host_list='$new_host_list'"

    section "Cleanup migration data at $new_host_list"

    if (( wait_before_cleanup && !cleanup_asked )); then
	wait_for_screener \
	    "$res" \
	    "$situation" \
	    "delayed" \
	    "cleanup at '$host_list' excluding '$host_list2'" \
	    "$(compute_timeout_after "$res" "$new_host_list $host_list $host_list2" "$wait_before_cleanup")"
	cleanup_asked=1
    fi

    call_hook tell_action migrate cleanup
    call_hook update_ticket migrate_cleanup running

    leave_resource "$res" "$new_host_list"
    injection_point
    for host in $host_list; do
	if (( cleanup_done[$host] )); then
	    echo "Clenup '$host' already done"
	    continue
	fi
	echo "CLEANUP LVs $host"
	local vg_name="$(get_vg "$host")"
	if [[ "$vg_name" != "" ]]; then
	    lv_remove "$host" "/dev/$vg_name/$res$tmp_suffix" 1
	    lv_remove "$host" "/dev/$vg_name/$res-copy" 1
	    lv_remove "$host" "/dev/$vg_name/$res$shrink_suffix_old" 1
	    cleanup_done[$host]=1
	fi
    done
    for host in $new_host_list; do
	echo "CLEANUP LVs $host"
	local vg_name="$(get_vg "$host")"
	if [[ "$vg_name" != "" ]]; then
	    lv_remove "$host" "/dev/$vg_name/$res" 1
	    sleep 3
	    cleanup_done[$host]=1
	fi
    done

    if (( do_split )); then
	section "Recompute host list"

	local new_host_list="$(get_augmented_host_list "$host_list $host_list2")"
	echo "Augmented host list: $new_host_list"
	host_list="$new_host_list"

	for host in $host_list; do
	    remote "$host" "marsadm wait-cluster || echo IGNORE cleanup"
	done

	section "Split cluster at $host_list"

	sleep 10
	_split_cluster "$host_list"
    fi

    call_hook tell_action migrate done
    call_hook update_ticket migrate_cleanup finished
}

######################################################################

# Generic background progress reporting

## enable_background_reporting
# Progress reporting to screener.
# Runs in the background, in parallel to forground processes
# like rsync or tar.
enable_background_reporting="${enable_background_reporting:-1}"

declare -g progress_flag=""

function start_background_progress_reporting
{
    local res="$1"
    local host="$2"
    local cmd="$3"

    if (( !enable_background_reporting )); then
	return
    fi

    # Multiple progress flags do not make sense in our use case.
    if [[ "$progress_flag" != "" ]]; then
	echo "Unexpected old value of progress_flag: '$progress_flag'"
	rm -f "$progress_flag"
	sleep 3
    fi
    echo "SCREENER_INFO="
    progress_flag="$football_logdir/progress.$res"
    progress_log="$football_logdir/progress.log"
    register_unlink "$progress_flag"
    echo "" > "$progress_flag"

    local old_msg=""
    while [[ -e "$progress_flag" ]]; do
	verbose=0
	local msg="$(remote "$host" "$cmd")" || break
	echo "$(date +%s) $res $msg" >> "$progress_log"
	if [[ "$msg" != "$old_msg" ]]; then
	    echo -e "\nSCREENER_INFO=$msg"
	    old_msg="$msg"
	fi
	local i
	for i in {1..60}; do
	    [[ -e "$progress_flag" ]] || break
	    sleep 1
	done
    done >> /dev/stderr 2>&1 &
}

function stop_background_progress_reporting
{
    if [[ "$progress_flag" != "" ]]; then
	echo "Removing progress_flag: '$progress_flag'"
	while [[ -e "$progress_flag" ]]; do
	    rm -f "$progress_flag"
	    sleep 3
	done
	unregister_unlink "$progress_flag"
	rm -f "$progress_flag"
	wait
	progress_flag=""
    fi
}

######################################################################

# Waiting for conditions

## condition_check_interval
# How often conditions should be re-evaluated.
condition_check_interval="${condition_check_interval:-180}" # Seconds

function wait_for_condition
{
    local lock_list="$1"
    local fn="$2"
    local txt="$3"
    local wait_time="${4:-$condition_check_interval}"

    local total_round=0
    echo "SCREENER_condition_WAIT $(date +%s) $(date) for condition: $(eval "echo \"$txt\"")"
    while true; do
	# Allow changes of config variables during runtime
	if (( ! ( total_round % 60 ) )); then
	    reconf
	else
	    reconf > /dev/null 2>&1
	fi
	reconf

	lock_hosts 1 "$lock_list" ALL
	local violated=0
	if ! eval "$fn"; then
	    echo "eval '$fn' rc=$?"
	    violated=1
	fi
	lock_hosts

	echo "violated=$violated"
	if (( !violated )); then
	    echo "SCREENER_condition_INFO: $(date) Condition is true: $(eval "echo \"$txt\"")"
	    break
	fi
	echo "SCREENER_condition_INFO: $(date) Condition is false: $(eval "echo \"$txt\"")"
	local keypress=0
	if [[ -t 0 ]]; then
	    echo "Press RETURN to interrupt / shorten the wait for condition: $(eval "echo \"$txt\"")"
	    local i
	    local dummy
	    for (( i = 0; i < wait_time; i++ )); do
		read -t 1 dummy
		keypress=$(( !$? ))
		(( keypress )) && break
	    done
	else
	    sleep $wait_time
	fi
	if (( keypress )); then
	    echo "KEYPRESS SCREENER_condition $(date +%s) $(date)"
	    break
	fi
	(( total_round++ ))
    done
    echo "SCREENER_condition_RESUME $(date +%s) $(date) condition: $(eval "echo \"$txt\"")"
}

function add_intent
{
    local intent="$1"
    local info="$2"

    echo "Adding intent '$intent' => '$info'" >> /dev/stderr
    register_unlink "$intent"
    echo "$info" > $intent
}

function check_intent
{
    local intent="$1"

    echo "Checking intent '$intent'" >> /dev/stderr
    if [[ -e "$intent" ]]; then
	echo "Removing doubled intent '$intent'" >> /dev/stderr
	rm -f $intent
	unregister_unlink "$intent"
    fi
}

## lease_time
# Any intents (e.g. for creation of new resources) are recorded.
# This is needed for race avoidance, when multiple resources
# are migrated in _parallel_ to the _same_ target.
# This might lead to livelocks when there would be no lease time
# after which the intents are regarded as "invalid".
lease_time="${lease_time:-3600}" # seconds

function sum_and_timeout_intents
{
    local pattern="$1"
    # modifies $sum

    local now="$(date +%s)"
    echo "Now '$now' checking for lease_time='$lease_time'" >> /dev/stderr
    local check
    for check in $pattern; do
	local intent_stamp="$(stat --printf='%Y' $check)"
	echo "Intent '$check' has timestamp='$intent_stamp'" >> /dev/stderr
	if (( intent_stamp + lease_time < now )); then
	    echo "Skipping outdated lease '$check'" >> /dev/stderr
	    rm -f $check
	    unregister_unlink "$check"
	    continue
	fi
	local value="$(< $check)"
	if [[ "$value" =~ ^[0-9]+$ ]]; then
	    echo "Adding intent '$check' value='$value'" >> /dev/stderr
	    (( sum += value ))
	else
	    echo "Counting intent '$check'" >> /dev/stderr
	    (( sum++ ))
	fi
    done
    echo "Sum: '$sum'" >> /dev/stderr
}

function remove_intent
{
    local intent="$1"

    echo "Removing intent '$intent' ('$(< $intent)')" >> /dev/stderr
    rm -f $intent
    unregister_unlink "$intent"
}

## limit_syncs
# Limit the number of actually running syncs by waiting
# until less than this number of syncs are running at any
# target host.
limit_syncs="${limit_syncs:-4}"

function compute_nr_syncs
{
    local host="$1"
    local add_res="$2"
    # return: $syncs

    if [[ "$add_res" != "" ]]; then
	local intent="$football_logdir/intent.syncs.$add_res"
	add_intent "$intent" "$host"
    fi
    local cmd="marsadm view-sync-rest all | grep '^[0-9]\+$' | grep -v '^0$' | wc -l"
    local count="$(remote "$host" "$cmd" 1)"
    echo "There are '$count' syncs running at '$host'" >> /dev/stderr
    cmd="marsadm view-my-resources all | grep ".---" | awk '{ print \$3; }'"
    local check
    for check in $(remote "$host" "$cmd"); do
	local intent="$football_logdir/intent.syncs.$check"
	check_intent "$intent"
    done
    local sum=0
    sum_and_timeout_intents "$football_logdir/intent.syncs.*"
    (( count += sum ))
    echo "Total intended _new_ sync count is / would be '$count' syncs at '$host'" >> /dev/stderr
    syncs="$count"
}

function generic_syncs_locked
{
    local res="$1"
    local host_list="$2"
    # return: $violated

    local host
    for host in $host_list; do
	local syncs=0
	compute_nr_syncs "$host" "$res"
	if (( syncs > 1 )) && [[ "$operation" =~ prep ]]; then
	    violated=2
	    return
	elif (( syncs > limit_syncs )); then
	    violated=1
	    remove_intent "$football_logdir/intent.syncs.$res" >> /dev/stderr
	    return
	fi
    done
    violated=0
}

function wait_for_syncs
{
    local res="$1"
    local host_list="$2"

    wait_for_condition \
	"$host_list" \
	"generic_syncs_locked \"$res\" \"$host_list\"" \
	"At most \$limit_syncs syncs at '$host_list'"
}

## limit_shrinks
# Limit the number of actually running shrinks by waiting
# until less than this number of shrinks are running at any
# target host.
limit_shrinks="${limit_shrinks:-1}"

## count_shrinks_by_tmp_mount
# Only count the temporary mounts.
# Otherwise, LVs are counted. The latter may yield false positives
# because LVs may be created in advance (e.g. at another cluster member)
count_shrinks_by_tmp_mount="${count_shrinks_by_tmp_mount:-1}"

function compute_nr_shrinks
{
    local host="$1"
    local add_res="$2"
    # return: $shrinks

    if [[ "$add_res" != "" ]]; then
	local intent="$football_logdir/intent.shrinks.$add_res"
	add_intent "$intent" "$host"
    fi
    # Check for the number of other shrink spaces
    local cmd=""
    local mnt="$(call_hook get_mountpoint "*")"
    if (( count_shrinks_by_tmp_mount )) && [[ "$mnt" != "" ]]; then
	echo "Counting shrinks at '$host' by mountpoints" >> /dev/stderr
	cmd="for i in $mnt$tmp_suffix; do mountpoint \$i; done | grep -v '$res$tmp_suffix' | grep ' is a mountpoint' | wc -l"
    fi
    if [[ "$cmd" = "" ]]; then
	echo "Counting shrinks at '$host' by LVs" >> /dev/stderr
	cmd="lvs | grep '.$tmp_suffix ' | grep -v '$res$tmp_suffix' | wc -l"
    fi
    local count="$(remote "$host" "$cmd" 1)"
    echo "There are $count shrinks running at $host" >> /dev/stderr
    local sum=0
    sum_and_timeout_intents "$football_logdir/intent.shrinks.*"
    (( count += sum ))
    echo "Total intended _new_ shrink count would be $count at $host" >> /dev/stderr
    shrinks="$count"
}

function generic_shrinks_locked
{
    local res="$1"
    local host_list="$2"
    # return: $violated

    local host
    for host in $host_list; do
	# Always accept the _own_ shrink space, unconditionally
	local cmd="lvs | grep '$res$tmp_suffix'"
	if remote "$host" "$cmd" 1 >> /dev/stderr; then
	    continue
	fi
	local shrinks=0
	compute_nr_shrinks "$host" "$res"
	if (( shrinks > limit_shrinks )); then
	    violated=1
	    remove_intent "$football_logdir/intent.shrinks.$res" >> /dev/stderr
	    return
	fi
    done
    violated=0
}

function wait_for_shrinks
{
    local res="$1"
    local host="$2"

    wait_for_condition \
	"$host" \
	"generic_shrinks_locked \"$res\" \"$host\"" \
	"At most \$limit_shrinks shrinks at '$host'"
}

## limit_mars_logfile
# Dont handover when too much logfile data is missing at the
# new primary site.
limit_mars_logfile="${limit_mars_logfile:-1024}" # MiB

function get_logfile_size
{
    local res="$1"
    local host="$2"

    local cmd="marsadm view-work-rest $res | grep '^[0-9]\+$'"
    local amount="$(remote "$host" "$cmd" 1)"
    echo "There is $amount KiB logfile data at $host resource $res" >> /dev/stderr
    echo "$(( amount / 1024 ))"
}

function generic_logfile_locked
{
    local res="$1"
    local host_list="$2"

    local host
    for host in $host_list; do
	local amount="$(get_logfile_size "$res" "$host")"
	if (( amount > limit_mars_logfile )) ; then
	    echo 1
	    return
	fi
    done
    echo 0
}

function wait_for_logfile
{
    local res="$1"
    local host_list="$2"

    wait_for_condition \
	"$host_list" \
	"generic_logfile_locked \"$res\" \"$host_list\"" \
	"At most \$limit_mars_logfile MiB logfile data at $res on '$host_list'"
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
	fail "cannot determine lv_path" "$illegal_status"

    vg_name="$(echo "$lv_path" | cut -d/ -f3)" || fail "cannot determine vg_name" "$illegal_status"

    echo "Determined the following VG name: \"$vg_name\""
    echo "Determined the following LV path: \"$lv_path\""

    df="$(remote "$src_hyper" "df $mnt" | grep "/dev/")" || fail "cannot determine df data" "$illegal_status"
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
	target_space="${target_space:-$(( used_space * 100 / target_percent + 1 ))}" || fail "cannot compute target_space" "$illegal_status"
	;;
    *)
	fail "illegal syntax \$target_percent='$target_percent'" "$illegal_status"
	;;
    esac
    (( target_space < min_space )) && target_space=$min_space

    echo "Determined USED  filesystem space at $src_hyper: $used_space"
    echo "Determined TOTAL filesystem space at $src_hyper: $total_space"
    echo "Computed TARGET  filesystem space at $dst_primary: $target_space"
}

## shrink_min_ram_gb
# When set, check that the target machines for shrinking
# have enough RAM.
# Rationale: even incremental rsync needs the Dentry cache of the
# kernel. When there is not enough RAM, and when there are some millions
# of inodes, the customer downtime may rise to some hours or even some days
# instead of some minutes (only when the detnry+inode cache does not
# fit into kernel memory <<<=== this is the cruscial point)
shrink_min_ram_gb="${shrink_min_ram_gb:-0}" # GiB

function check_shrinking
{
    # works on global variables
    determine_space
    if (( target_space >= total_space )); then
	echo "No need for shrinking the LV space of $res"
	(( !force )) && exit 0
    fi
    local list="$target_primary $target_secondary"
    if ! [[ "$list" =~ [A-Za-z0-9_] ]]; then
	list="$primary $secondary_list"
    fi
    for host in $list; do
	echo "Checking shrink precondtions at '$host'"
	check_vg_space "$host" "$target_space" "$res" "$tmp_suffix"
	if (( shrink_min_ram_gb > 0 )); then
	    local ram_gb="$(get_ram_gb "$host")"
	    if (( ram_gb < shrink_min_ram_gb )); then
		fail "Cannot shrink: host '$host' has less RAM than '$shrink_min_ram_gb' GiB" $illegal_status
	    fi
	fi
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

## reuse_lv_check
# When set, this command is executed for checking whether
# the LV can be reused.
reuse_lv_check="${reuse_lv_check:-xfs_db -c sb -c print -r}"

## do_quota
# Transfer xfs quota information.
# 0 = off
# 1 = global xfs quota transfer
# 2 = additionally local one
do_quota="${do_quota:-2}"

## xfs_dump_dir
# Temporary space for keeping xfs quota dumps.
xfs_dump_dir="${xfs_dump_dir:-$football_backup_dir/xfs-quota-$start_stamp}"

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

    if (( !do_quota )); then
	return
    fi

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
    if (( reuse_lv )); then
	# check whether LV already exists
	if remote "$host" "[[ -e /dev/$vg_name/${lv_name}$tmp_suffix ]]" 1; then
	    if [[ "$reuse_lv_check" != "" ]]; then
		local cmd="$reuse_lv_check /dev/$vg_name/${lv_name}$tmp_suffix"
		echo "Checking: $cmd"
		if remote "$host" "$cmd" 1; then
		    echo "Checked: reusing already existing LV /dev/$vg_name/${lv_name}$tmp_suffix on '$host'"
		    return
		fi
	    else
		echo "Blindly reusing already existing LV /dev/$vg_name/${lv_name}$tmp_suffix on '$host'"
		return
	    fi
	fi
    else
	remote "$host" "if [[ -e /dev/$vg_name/${lv_name}$shrink_suffix_old ]]; then echo \"REFUSING to overwrite /dev/$vg_name/${lv_name}$shrink_suffix_old on $host - Do this by hand\"; exit -1; fi"
    fi
    call_hook disconnect "$host" "$lv_name"
    remote "$host" "if [[ -e /dev/$vg_name/${lv_name}$tmp_suffix ]]; then lvremove $lvremove_opt /dev/$vg_name/${lv_name}$tmp_suffix; fi"
    injection_point

    # do it
    section "Creating shrink space on $host"

    local extra="$(get_stripe_extra "$host" "$vg_name")"
    remote "$host" "lvcreate -L ${size}k $extra -n ${lv_name}$tmp_suffix $vg_name"
    injection_point
    sleep 1
    remote "$host" "$mkfs_cmd /dev/$vg_name/${lv_name}$tmp_suffix"
    remove_intent "$football_logdir/intent.shrinks.$lv_name" >> /dev/stderr
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
	injection_point
    fi
}

declare -g copy_initial=0

## shortcut_tar_percent
# Percentage when a shrink space should no longer be considered
# as "inital" (or empty).
shortcut_tar_percent="${shortcut_tar_percent:-5}"

function copy_data
{
    local hyper="$1"
    local lv_name="$2"
    local suffix="${3:-$tmp_suffix}"
    local nice="${4:-$rsync_nice}"
    local add_opt="${5:-$rsync_opt_prepare}"
    local repeat_count="${6:-$rsync_repeat_prepare}"

    local time_cmd="/usr/bin/time -f 'rss=%M elapsed=%e'"

    section "COPY DATA via rsync / tar"

    local mnt="$(call_hook get_mountpoint "$lv_name")"
    local percent="$(remote "$hyper" "mountpoint $mnt$suffix/ && df $mnt$suffix/" 1 | grep -o "[0-9]\+%" | sed 's/%//')"
    echo "Mountpoint '$mnt$suffix/' is filled by '$percent' percent"
    if (( shortcut_tar_percent > 0 && percent > shortcut_tar_percent )); then
	echo "Treat as non-initial rsync"
	(( copy_initial++ ))
    fi

    local cmd="set -o pipefail; for i in {1..$repeat_count}; do echo round=\$i; $nice $time_cmd rsync $rsync_opt $add_opt $mnt/ $mnt$suffix/ | stdbuf --input=0 --output=L awk 'BEGIN{ RS=\"[\\r\\n]\"; } { if (\$0 ~ /xfr\#|\%.*[0-9]+:[0-9]+:[0-9]+ /) { if (c++ % $rsync_skip_lines == 0) { print \$0; } } else { print \$0; } }'; rc=\$?; echo rc=\$rc; if (( !rc || rc == 24 )); then exit 0; fi; echo RESTARTING \$(date); done; echo FAIL; exit -1"
    if (( use_tar >= 3 || ( !copy_initial++ && use_tar) )); then
	# Ignore so-called "fatal" errors only when use_tar == 1.
	# In this case, the next round with rsync will fix any problems.
	# When tar is the only transport, we cannot ignore fatal return codes,
	# even of tar is tending to report false-positives.
	local max_rc=1
	if (( !tar_is_fixed && use_tar == 1 )); then
	    max_rc=2
	fi
	local tar_cmd="(cd $mnt/ && $tar_exe -cS --hard-dereference $tar_options_src -g $tar_state_dir/tar.$lv_name -f - .) | (${buffer_cmd:-cat}) | (cd $mnt$suffix/ && $tar_exe -xp $tar_options_dst --incremental -f -)"
	cmd="set -o pipefail; $tar_cmd; rc=\$?; echo rc=\$rc; if (( rc >= 0 && rc <= $max_rc )); then exit 0; fi; echo FAIL; exit -1"
    fi

    start_background_progress_reporting "$lv_name" "$hyper" "df $mnt$suffix | grep -o '[0-9]\+%'"
    remote "$hyper" "$cmd"
    injection_point
    stop_background_progress_reporting
    transfer_quota "$hyper" "$lv_name" "$mnt" "$mnt$suffix"
    remote "$hyper" "sync"
}

## max_rsync_downtime
# When set, check the _expected_ duration of customer downtime.
# if it takes longer than this limit, abort without causing
# customer downtime.
# Afterward, sysadmins need to decide what to do:
# For example, move the resource to faster hardware with more RAM, or similar.
max_rsync_downtime="${max_rsync_downtime:-0}" # seconds

## merge_shrink_secondaries
# This is only needed when targets are not yet pre-merged.
merge_shrink_secondaries="${merge_shrink_secondaries:-0}"

declare -g merged=0

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
    call_hook resource_info "$lv_name"
    call_hook resource_info "$lv_name" "$suffix"

    section "Last online incremental rsync"

    remote "$hyper" "rm -f $tar_state_dir/tar.$lv_name" 1
    copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_prepare" "$rsync_repeat_prepare"
    # repeat for better dentry caching
    copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_prepare" "$rsync_repeat_prepare"

    call_hook save_local_quota "$hyper" "$lv_name"

    # go offline
    section "Go offline"

    local full_list="$(get_full_list "$primary $secondary_list")"

    # repeat for better dentry caching
    wait_for_screener "$res" "shrink" "waiting" "$hyper $lv_name" "" "$cache_repeat_lapse" \
	copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_prepare" "$rsync_repeat_prepare"

    if (( max_rsync_downtime > 0 )); then
	local start_stamp="$(date +%s)"
	copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_prepare" "$rsync_repeat_prepare"
	local end_stamp="$(date +%s)"
	local elapsed=$(( end_stamp - start_stamp ))
	echo "Probing took '$elapsed' seconds from '$start_stamp' to '$end_stamp'"
	if (( elapsed > max_rsync_downtime )); then
	    fail "Probed rsync took too long: $elapsed seconds"
	fi
    fi

    call_hook want_downtime "$res" 1
    call_hook tell_action shrink finish
    call_hook update_ticket shrink_finish running

    lock_hosts 1 "$full_list" ALL

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

	remote "$primary" "marsadm primary --ignore-sync $lv_name; marsadm primary $lv_name" 1
	if [[ "$primary" != "$hyper" ]]; then
	# create remote devices instead
	    mars_dev="$(call_hook connect "$primary" "$hyper" "$lv_name" 2>&1 | tee -a /dev/stderr | grep "^NEW_DEV" | cut -d: -f2)"
	    echo "using tmp mars dev '$mars_dev'"
	    [[ "$mars_dev" = "" ]] && fail "cannot setup remote mars device between hosts '$primary' => '$hyper'"
	fi
	remote "$hyper" "mount $mount_opts $mars_dev $mnt/"
	injection_point
    fi

    section "Final rsync / tar"

    call_hook resource_info "$lv_name"
    call_hook resource_info "$lv_name" "$suffix"

    copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_hot" "$rsync_repeat_hot"

    call_hook resource_info "$lv_name"
    call_hook resource_info "$lv_name" "$suffix"

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
    sleep 10
    remote "$primary" "marsadm secondary $lv_name"
    injection_point

    for host in $full_list; do
	call_hook save_resource_state "$host" "$lv_name"
    done

    section "IMPORTANT: destroying the MARS resources at $full_list"
    echo "In case of failure, you can re-establish MARS resources by hand."
    echo ""

    failure_handler=failure_rebuild_mars

    delete_resource "$lv_name" "$full_list"
    call_hook restore_resource_state "$primary" "$lv_name"
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
	local rename_cmd="if [[ -e /dev/$vg_name/$lv_name$shrink_suffix_old ]] && [[ -e /dev/$vg_name/$lv_name ]]; then lvremove $lvremove_opt /dev/$vg_name/$lv_name$shrink_suffix_old; fi"
	rename_cmd+="; lvrename $vg_name $lv_name ${lv_name}$shrink_suffix_old || echo IGNORE backup creation"
	rename_cmd+="; if ! [[ -e /dev/$vg_name/$lv_name ]]; then lvrename $vg_name $lv_name$suffix $lv_name; fi"
	remote "$host" "$rename_cmd"
	injection_point
    done

    wait

    remote "$primary" "if ! [[ -e /dev/mars/$lv_name ]]; then marsadm create-resource --force $lv_name $dev; fi"
    injection_point
    call_hook restore_resource_state "$primary" "$lv_name"
    remote "$primary" "marsadm primary --ignore-sync $lv_name; marsadm primary $lv_name" 1

    section "IMPORTANT: go online again"
    echo "In case of failure, you can re-establish MARS resources by hand."
    echo ""

    call_hook resource_start "$primary" "$lv_name"
    call_hook resource_info "$lv_name"
    injection_point

    failure_handler=""
    remote "$hyper" "rm -f $tar_state_dir/tar.$lv_name" 1

    call_hook restore_local_quota "$hyper" "$lv_name"

    if (( merge_shrink_secondaries )); then
	merge_cluster "$lv_name" "$primary $secondary_list" "$secondary_list"
    fi

    section "Re-create the MARS replicas"

    for host in $secondary_list; do
	cleanup_done[$host]=0
	vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
	dev="/dev/$vg_name/${lv_name}"
	if exists_hook join_resource; then
	    call_hook join_resource "$primary" "$host" "$lv_name" "$dev"
	else
	    remote "$host" "marsadm $(call_hook ssh_port "$host" 1) join-resource $lv_name $dev"
	fi
	injection_point
    done

    lock_hosts

    section "Checking new container"

    call_hook resource_check "$lv_name"
    call_hook report_downtime "$res" 0
    call_hook want_downtime "$res" 0
    call_hook update_ticket shrink_finish finished
}

function cleanup_old_remains
{
    local host_list="$1"
    local lv_name="$2"

    section "Cleanup any UNUSED LVs (retaining ordinary ones)"

    local host
    for host in $host_list; do
	if (( cleanup_done[$host] )); then
	    echo "Skipping already done '$host'"
	    continue
	fi
	local vg_name="$(get_vg "$host")"
	if [[ "$vg_name" != "" ]]; then
	    if (( wait_before_cleanup && !cleanup_asked )); then
		wait_for_screener \
		    "$lv_name" \
		    "cleanup" \
		    "delayed" \
		    "cleanup old remains at '$host_list'" \
		    "$(compute_timeout_after "$lv_name" "$host_list" "$wait_before_cleanup")"
		cleanup_asked=1
	    fi
	    make_tmp_umount "$host" "$host" "$lv_name" "$tmp_suffix"
	    section "Removing LVs from $host"
	    lv_remove "$host" "/dev/$vg_name/${lv_name}$tmp_suffix" 1
	    lv_remove "$host" "/dev/$vg_name/${lv_name}$shrink_suffix_old" 1
	else
	    echo "ERROR: cannot determine VG for host $host" >> /dev/stderr
	fi
    done
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
	local vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'" "$illegal_status"
	local dev="/dev/$vg_name/$lv_name"
	remote "$host" "lvresize -L ${size}k $dev"
    done
    for host in $primary $secondary_list; do
	remote "$host" "marsadm wait-cluster"
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
    phase migrate_prepare

    call_hook tell_action migrate init
    call_hook tell_action migrate prepare
    call_hook update_ticket migrate_prepare running

    migration_prepare "$res" "$primary" "$secondary_list" "$target_primary" "$target_secondary" "$extra_secondary"
}

function wait_uptodate
{
    local update_ticket="${1:-1}"

    phase wait_uptodate

    wait_resource_uptodate "$target_primary $target_secondary" "$res"
    if (( update_ticket )); then
	call_hook update_ticket migrate_prepare finished
    fi
}

function migrate_check
{
    call_hook check_migrate "$primary" "$target_primary" "$res"
    injection_point
}

function migrate_finish
{
    phase migrate_finish

    migrate_resource "$primary" "$secondary_list" "$target_primary" "$target_secondary" "$res"
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

## migrate_two_phase
# This is useful when the new hardware has a better replication network,
# e.g. 10GBit uplink instead of 1GBit.
# Instead of starting two or more syncs in parallel on the old hardware,
# run the syncs in two phases:
# 1. migrate data to the new primary only.
# 1b. handover to new primary.
# 2. now start migration of data to the new secondaries, over the better
# network attachment of the new hardware.
migrate_two_phase="${migrate_two_phase:-0}"

function migrate
{
    local do_cleanup="${1:-1}"
    local two_phase="${2:-$migrate_two_phase}"

    echo "Migrate do_cleanup=$do_cleanup two_phase=$two_phase"
    local old_target_secondary="$target_secondary"
    if (( two_phase )) && [[ "$old_target_secondary" != "" ]]; then
	echo "Migrating in two phases"
	declare -g extra_secondary="$target_secondary"
	target_secondary=""
    fi
    migrate_prepare
    wait_uptodate
    migrate_finish
    if (( two_phase )) && [[ "$old_target_secondary" != "" ]]; then
	echo "Migrating in two phases"
	old_primary="$primary"
	old_secondary_list="$secondary_list"
	target_secondary="$old_target_secondary"
	declare -g extra_secondary=""
	primary="$target_primary"
	secondary_list=""
	migrate 0 0
	primary="$old_primary"
	secondary_list="$old_secondary_list"
    fi
    if (( do_cleanup )); then
	migrate_cleanup "$primary $secondary_list" "$target_primary $target_secondary" "$res"
	cleanup_old_remains "$primary $secondary_list" "$res"
    fi
}

### for shrinking

function check_shrink_unnecessary
{
    local res="$1"
    local host_list="$2"

    local ok=0
    local host
    for host in $host_list; do
	local cmd="lvs | grep '$res$shrink_suffix_old'"
	local present="$(remote "$host" "$cmd")"
	echo "Backup LVs at host $host: '$present'"
	[[ "$present" = "" ]] && (( ok++ ))
	local mars_resource_exists="$(remote "$host" "marsadm view-disk-present $res" | grep '^[0-9]\+$')"
	echo "MARS replica at host $host: '$mars_resource_exists'"
	(( !mars_resource_exists )) && (( ok++ ))
    done
    return $ok
}

function shrink_prepare
{
    if check_shrink_unnecessary "$res" "$primary $secondary_list"; then
	echo "No need for shrink_prepare: backup LVs '$res$shrink_suffix_old' already present at '$primary $secondary_list'"
	echo "If you want to force a shrink, run lv_cleanup first."
	return
    fi

    phase shrink_prepare

    section "Wait when too many shrinks are already running"

    wait_for_shrinks "$res" "$primary"

    section "Determine shrink space"

    call_hook tell_action shrink init
    determine_space

    section "Start LVM and FS operations"

    call_hook tell_action shrink prepare
    call_hook update_ticket shrink_prepare running
    create_shrink_space_all "$primary $secondary_list" "$res" "$target_space"
    make_tmp_mount "$hyper" "$primary" "$res"
    copy_data "$hyper" "$res" "$tmp_suffix" "$rsync_nice" "$rsync_opt_prepare" "$rsync_repeat_prepare"
    call_hook save_local_quota "$hyper" "$res"
    injection_point
    if (( !reuse_mount )); then
	make_tmp_umount "$hyper" "$primary" "$res"
    fi
    call_hook update_ticket shrink_prepare finished
}

function shrink_finish
{
    if check_shrink_unnecessary "$res" "$primary $secondary_list"; then
	echo "No need for shrink_finish: backup LVs '$res$shrink_suffix_old' already present at '$primary $secondary_list'"
	echo "If you want to force a shrink, run lv_cleanup first."
	return
    fi

    phase shrink_finish

    hot_phase "$hyper" "$primary" "$secondary_list" "$res"
}

function shrink_cleanup
{
    phase shrink_cleanup

    call_hook tell_action shrink cleanup
    call_hook update_ticket shrink_cleanup running
    cleanup_old_remains "$primary $secondary_list" "$res"
    call_hook tell_action shrink done
    call_hook update_ticket shrink_cleanup finished
}

### for extending

function extend_stack
{
    phase extend

    call_hook tell_action extend init
    determine_space
    call_hook tell_action extend prepare
    extend_fs "$hyper" "$primary" "$secondary_list" "$res" "$target_space"
    call_hook tell_action extend done
}

### combined operations

## migrate_always_all
# By default, migrate+shrink creates only 1 replica during the initial
# migration.
# When setting this, all replicas are created, which improves resilience,
# but worsens network performance.
migrate_always_all="${migrate_always_all:-0}"

## migrate_early_cleanup
# Early cleanup of old replicas when using migrate_always_all or
# migrate_two_phase.
# Only reasonable when combined with migrate+shrink.
# This is slightly less safe, but saves time when you want to
# decommission old hardware as fast as popssible.
# Early cleanup of the old replicase will only be done when
# at least 2 replicas are available at the new (target) side.
# These two new replicas can be created either by
#  a) migrate_always_all=1 or
#  b) migrate_two_phase=1 or automatically selected (or not) via
#  c) auto_two_phase=1
migrate_early_cleanup="${migrate_early_cleanup:-1}"

function migrate_plus_shrink
{
    local go_back="${1:-0}"

    local old_hyper="$hyper"
    local old_primary="$primary"
    local old_secondary="$secondary_list"
    if (( go_back )); then
	# completely unused
	target_secondary=""
	local tmp_primary="$target_primary"
	local status_file="$football_logdir/initial.$res.status"
	if ! [[ -s "$status_file" ]]; then
	    echo "$old_primary $old_secondary" > "$status_file"
	fi
    fi
    local old_target_secondary="$target_secondary"
    sub_operation="migrate"
    migrate_check
    if [[ "$primary" != "$target_primary" ]] && [[ "$primary" != "$target_secondary" ]]; then
	if (( migrate_two_phase || migrate_always_all )); then
	    migrate 1 "$migrate_two_phase"
	    if (( migrate_early_cleanup )); then
		call_hook invalidate_caches
		echo "EARLY_CLEANUP $res $old_primary $old_secondary => $target_primary $target_secondary"
		migrate_cleanup "$old_primary $old_secondary" "$target_primary $target_secondary" "$res" 1 "early_cleanup"
		injection_point
		cleanup_asked=0
	    fi
	else
	    # Less network traffic:
	    # Migrate to only one target => new secondary will be created
	    # again at shrink 
	    target_secondary=""
	    migrate 0 0
	fi
	call_hook invalidate_caches
	if (( go_back )); then
	    target_secondary=""
	else
	    target_secondary="$old_target_secondary"
	fi
	declare -g -A hypervisor_host=()
	declare -g -A storage_host=()
    else
	echo "Skipping the 'migrate' part, continue with 'shrink'"
    fi
    sub_operation="shrink"
    target_hyper="$(get_hyper "$res")" || fail "New hypervisor hostname canot be determined"
    echo "SWAP $old_primary[$old_hyper] $old_secondary => $target_primary[$target_hyper] $target_secondary"
    hyper="$target_hyper"
    primary="$target_primary"
    secondary_list="$target_secondary"
    shrink_prepare
    shrink_finish
    if (( go_back )); then
	if [[ -s "$status_file" ]]; then
	    read old_primary old_secondary < "$status_file"
	fi
	echo "GO_BACK $target_primary[$target_hyper] => $old_primary[$old_hyper] $old_secondary"
	migrate_cleanup "$old_primary $old_secondary" "$target_primary $target_secondary" "$res" 0
	hyper="$old_hyper"
	primary="$target_primary"
	secondary_list=""
	target_primary="$old_primary"
	target_secondary="$old_secondary"
	call_hook invalidate_caches
	sub_operation="migrate"
	migrate_prepare
	wait_uptodate
	migrate_finish
	old_primary="$tmp_primary"
	old_secondary=""
    else
	wait_uptodate 0
    fi
    migrate_cleanup "$old_primary $old_secondary" "$target_primary $target_secondary" "$res"
    cleanup_old_remains "$old_primary $old_secondary $target_primary $target_secondary" "$res"
    if (( go_back )); then
	rm -f "$status_file"
    fi
    call_hook tell_action migrate done
    call_hook tell_action shrink done
}

### global actions

function lv_clean
{
    LV_cleanup "$primary" "$res" 1
}

######################################################################

# ssh

function get_real_ssh_user
{
    local raw="$(ssh-add -l)"
    # check for syntax username@host
    if [[ "$raw" =~ @ ]]; then
	echo "$raw" | grep -o '[^ ]\+@[^ ]\+' | sort -u | tail -1
	return
    fi
    # check for path to home directory
    if [[ "$raw" =~ /home/ ]]; then
	echo "$raw" | grep -o '/home/[^/ ]\+' | cut -d/ -f3 | sort -u | tail -1
	return
    fi
    # fallback to fingerprint
    echo "$raw" | grep -i -o '[0-9a-z]\+:[^ ]\+' | sed 's:/:_:g' | sort -u | tail -1
}

######################################################################

# MAIN: get and check parameters, determine hosts and resources, run actions

main_pid="$BASHPID"

commands_installed "$commands_needed"

declare -g -a argv=()

scan_vars "$@"

# This may be used for rewriting the global array $argv
call_hook rewrite_args >> /dev/stderr

scan_vars "${argv[@]}"

scan_args "${argv[@]}"

ssh-add -l >> /dev/stderr || fail "You must use ssh-agent and ssh-add with the proper SSH identities" "$illegal_status"

## user_name
# Normally automatically derived from ssh agent or from $LOGNAME.
# Please override this only when really necessary.
export user_name="${user_name:-$(get_real_ssh_user)}"
export user_name="${user_name:-$LOGNAME}"

## replace_ssh_id_file
# When set, replace current ssh user with this one.
# The new user should hot have a passphrase.
# Useful for logging out the original user (interrupting the original
# ssh agent chain).
replace_ssh_id_file="${replace_ssh_id_file:-}"

if [[ "$replace_ssh_id_file" != "" ]] && [[ "$replace_ssh_id_file" != "EMPTY" ]]; then
    echo "OLD ssh keys:"
    ssh-add -l
    echo "Replacing ssh agent"
    unset SSH_AGENT_PID
    agent_rc="$football_logdir/ssh-agent.rc"
    if [[ -s $agent_rc ]]; then
	echo "Reusing ssh-agent pid from '$agent_rc'"
	echo "$(< $agent_rc)"
	source $agent_rc
    fi
    if [[ "$SSH_AGENT_PID" != "" ]]; then
	echo "Check whether the common ssh agent process $SSH_AGENT_PID works"
	if ! ssh-add -l; then
	    echo "Did not work, will then fork a new one."
	    SSH_AGENT_PID=""
	fi
    fi
    if [[ "$SSH_AGENT_PID" = "" ]]; then
	echo "Forking new ssh-agent into '$agent_rc'"
	mkdir -p $football_logdir
	eval $(ssh-agent | tee $agent_rc)
	echo "Replacing new ssh users from file '$replace_ssh_id_file'"
	ssh-add -D
	ssh-add $replace_ssh_id_file || fail "ssh-add $replace_ssh_id_file status=$?"
	echo "NEW ssh keys:"
	ssh-add -l
    fi
    export replace_ssh_id_file="EMPTY"
fi >> /dev/stderr

# Delegate to screener when possible
if (( screener )) && [[ "$res" != "" ]]; then
    # disallow endless recursion
    export screener=0
    export title="$operation $res"
    if [[ "$3" != "" ]]; then
	export title+=" $3"
    fi
    shopt -s extglob
    exec $(dirname "$0")/screener.sh start "${res:-$1}" "$0" "${*//--screener?(=*)/}" --confirm=0
fi

for name in $plugin_command_list; do
    if [[ "${operation//-/_}" = "$name" ]]; then
	unset argv[0]
	call_hook ${name#*_} "${argv[@]}"
	exit $?
    fi
done

mkdir -p "$football_logdir"

{
echo "user_name=$user_name $0 $@ => ${argv[@]}"
main_pid="$BASHPID"

if ! git describe --tags; then
    echo "$0 version 2.0"
fi

for sig in $trap_signals; do
    trap "trap_context=\"$sig MAIN\" fail" $sig
done

sub_operation="${operation//[+_]*/}"

call_hook pre_init "${argv[@]}"

# special (manual) operations

case "${operation//-/_}" in
test_delete_resource)
  test_delete_resource
  exit 0
  ;;

manual_call_hook)
  scan_vars "$@"
  hook="$2"
  shift 2
  echo "Hook '$hook' '$@'" >> /dev/stderr
  call_hook "$hook" "$@"
  exit $?
  ;;

manual_config_update)
  call_hook update_cm3_config "$host"
  exit $?
  ;;

manual_merge_cluster)
  shift
  manual_merge_cluster "$@"
  exit $?
  ;;

manual_split_cluster)
  shift
  _split_cluster "$*"
  exit $?
  ;;

repair_vm)
  enable_failure_restart_vm=1
  failure_restart_vm "$primary $secondary_list" "" "$res"
  exit $?
  ;;

repair_mars)
  enable_failure_restart_vm=1
  enable_failure_rebuild_mars=1
  failure_rebuild_mars "$primary $secondary_list" "" "$res"
  exit $?
  ;;

manual_lock)
  shift
  item="$1"
  shift
  lock_hosts 1 "$*" "$item"
  locked_hosts=""
  exit $?
  ;;

manual_unlock)
  shift
  item="$1"
  shift
  lock_hosts 0 "$*" "$item"
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
    fail "No resource name parameter given" "$illegal_status"
fi

if [[ "$pre_hand" != "" ]]; then
    phase pre-handover "Pre-Handover of '$res' to '$pre_hand'"
    # Here are no further checks because handover is _defined_ that
    # it _must_ be working as a precondition.
    # In strange situations, this might be used for cleaning up the situation.
    do_confirm
    (
	main_pid="$BASHPID"
	handover "$pre_hand" "$res"
    )
    echo "Handover status=$?"
    phase main "$0 $*"
fi

hyper="$(get_hyper "$res")" || fail "No current hypervisor hostname can be determined" "$illegal_status"

echo "Determined the following CURRENT hypervisor: \"$hyper\""

primary="$(get_store "$res")" || fail "No current primary hostname can be determined" "$illegal_status"

echo "Determined the following CURRENT primary: \"$primary\""

call_hook determine_variables

for host in $hyper $primary; do
    ping $ping_opts "$host" > /dev/null || fail "Host '$host' is not pingable" "$illegal_status"
done

remote "$primary" "mountpoint /mars"
remote "$primary" "[[ -d /mars/ips/ ]]"
remote "$primary" "marsadm view $res"

if ! [[ "$operation" =~ manual ]]; then
    if (( $(remote "$primary" "marsadm view-is-primary $res") <= 0 )); then
	fail "Resource '$res' on host '$primary' is not in PRIMARY role" "$illegal_status"
    fi
    mnt="$(call_hook get_mountpoint "$res")"
    if [[ "$mnt" != "" ]]; then
	remote "$hyper" "mountpoint $mnt"
    fi
fi

secondary_list="$(remote "$primary" "marsadm view-resource-members $res" | { grep -v "^$primary$" | grep -v "^$target_primary$"  | grep -v "^$target_secondary$"|| true; })" || fail "cannot determine secondary_list" "$illegal_status"
secondary_list="$(echo $secondary_list)"

echo "Determined the following secondaries: '$secondary_list'"

for host in $secondary_list; do
    ping $ping_opts "$host" || fail "Host '$host' is not pingable" "$illegal_status"
    remote "$host" "mountpoint /mars > /dev/null"
    remote "$host" "[[ -d /mars/ips/ ]]"
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
if [[ "$operation" =~ ^(shrink|shrink_prepare|migrate\+shrink)$ ]]; then
    check_shrinking
elif [[ "$operation" =~ extend|expand ]]; then
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
echo "START $(date) main_pid=$main_pid"

echo "SCREENER_LOCATION="
echo "SCREENER_INFO="

if [[ "${operation//-/_}" =~ $start_regex ]]; then
    call_hook update_ticket "$operation" general.running
    call_hook football_start "$0" "$@"
fi

case "${operation//-/_}" in
migrate_prepare)
  migrate_prepare
  ;;
migrate_wait)
  wait_uptodate
  ;;
migrate_finish)
  migrate_check
  migrate_finish
  ;;
migrate)
  migrate_check
  migrate
  ;;
migrate_cleanup)
  migrate_clean
  ;;


manual_handover)
  handover "$target_primary" "$res"
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
  target_primary="$primary" target_secondary="$secondary_list" wait_uptodate 0
  if (( wait_before_cleanup )); then
      wait_for_screener "$res" "cleanup" "delayed" "shrink $res" "$(compute_timeout_after "$res" "$primary $secondary_list" "$wait_before_cleanup")"
  fi
  shrink_cleanup
  ;;

extend|expand)
  extend_stack
  ;;

lv_cleanup)
  lv_clean
  ;;

migrate+shrink)
  migrate_plus_shrink
  ;;

migrate+shrink+back)
  migrate_plus_shrink 1
  ;;

*)
  helpme
  fail "Unknown operation '$operation'" "$illegal_status"
  ;;
esac

if [[ "$post_hand" != "" ]]; then
    phase post-handover "Post-Handover of '$res' to '$post_hand'"
    do_confirm
    handover "$post_hand" "$res"
    echo "Handover status=$?"
fi

phase done "$0 $*"

if [[ "${operation//-/_}" =~ $finished_regex ]]; then
    call_hook football_finished 0 "$0" "$@"
    call_hook update_ticket "$operation" general.finished
    operation=""
fi

if [[ -d "$football_logdir" ]]; then
    echo "Purging '$football_logdir'"
    ($(dirname "$0")/./screener.sh purge "$football_logdir")
fi

echo "DONE $(date)"
exit 0
} 2>&1 | {
    for sig in $trap_signals; do
	trap "" $sig
    done
    log "$football_logdir" "logs$args_info.$start_stamp.$user_name.log"
}
exit $?
