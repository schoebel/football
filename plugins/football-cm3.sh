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

###########################################

# Container Football

# 1&1 specific plugin / hooks for working with Jessie icpu conventions and cm3
#
# This script must be sourced from the main script.

# Guard agains multiple sourcing
[[ "${files[cm3]}" != "" ]] && return

function cm3_describe_plugin
{
    cat <<EOF

PLUGIN football-cm3

   1&1 specfic plugin for dealing with the cm3 cluster manager
   and its concrete operating enviroment (singleton instance).

   Current maximum cluster size limit: $max_cluster_size

   Maximum #syncs running before migration can start: $max_syncs

   Following marsadm --version must be installed: $needed_marsadm

   Following mars kernel modules must be loaded: $needed_mars

Specific actions for plugin football-cm3:

  $0 clustertool {GET|PUT} <url>
    Call through to the clustertool via REST.
    Useful for manual inspection and repair.

Specific features with plugin football-cm3:

  - Parameter syntax "cluster123" instead of "icpu456 icpu457"
    This is an alternate specification syntax, which is
    automatically replaced with the real machine names.
    It tries to minimize datacenter cross-traffic by
    taking the new \$target_primary at the same datacenter
    location where the container is currenty running.

EOF
   show_vars "${files[cm3]}"
}

register_description "cm3"

###########################################

## enable_cm3
# ShaHoLin-specifc plugin for working with the infong platform
# (istore, icpu, infong) via 1&1-specific clustermanager cm3
# and related toolsets. Much of it is bound to a singleton database
# instance (clustermw & siblings).
enable_cm3="${enable_cm3:-$(if [[ "$0" =~ tetris ]]; then echo 1; else echo 0; fi)}"

(( enable_cm3 )) || return 0

## skip_resource_ping
# Enable this only for testing. Normally, a resource name denotes a
# container name == machine name which must be runnuing as a precondition,
# und thus must be pingable over network.
skip_resource_ping="${skip_resource_ping:-0}"

commands_installed "curl json_pp bc"

function cm3_get_mountpoint
{
    local res="$1"
    echo "/vol/$res"
}

function cm3_get_hyper
{
    local res="$1"

    remote "$res" "source /lib/ui-config-framework/bash-includes; __config_getConfigVar HWNODE_NAME; echo \$HWNODE_NAME | cut -d. -f1"
}

function cm3_get_store
{
    local host="$1"
    
    try="$(remote "$host" "source /lib/ui-config-framework/bash-includes; __config_getConfigVar CLUSTER_STORAGEHOST; echo \$CLUSTER_STORAGEHOST | cut -d. -f1")"
    if [[ "$try" != "" ]]; then
	echo "$try"
	return
    fi
    # fallback to nc over iscsi network
    try="$(remote "$host" "nc \$(iscsiadm -m session -o show | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' | tail -1) 101 2>/dev/null | cut -d. -f1" 1)"
    if [[ "$try" != "" ]]; then
	echo "$try"
	return
    fi
    # fallback to indirect retrieval
    local hyper="$(cm3_get_hyper "$host")"
    if [[ "$hyper" != "" ]] && [[ "$hyper" != "$host" ]]; then
	cm3_get_store "$hyper"
    fi
}

function cm3_get_vg
{
    local host="$1"
    
    remote "$host" "vgs | awk '{ print \$1; }' | grep 'vginfong\|vg[0-9]\+[ab]'"
}

function cm3_lv_remove
{
    local host="$1"
    local path="$2"
    local fail_ignore="${3:-0}"

    # Assumption: old istores will never become targets anymore.
    # Therefore, keep old LVs as a backup.
    if [[ "$host" =~ istore ]]; then
	remote "$host" "lvrename $path $path.old" 1
    else
	remote "$host" "lvremove $lvremove_opt $path" 1
    fi
    local rc=$?
    if (( fail_ignore )); then
	return 0
    fi
    return $rc
}

## business_hours
# When set, critical sections are only entered during certain
# days of the week, and/or during certain hours.
# This is a regex matching against "date +%u_%H".
# Example regex: [1-5]_(0[8-9]|1[0-8])
# This means Monday to Friday from 8 to 18 o'clock.
business_hours="${business_hours:-}"

function cm3_resource_locked
{
    local res="$1"

    # 1. is there a global lock?
    if [[ -e "$football_logdir/lock" ]] || [[ -e "$screener_logdir/lock" ]] ; then
	echo "RESOURCE_LOCK $(date +%s) $(date) GLOBAL LOCK" >> /dev/stderr
	echo 1
	return
    fi
    # 2. is there a resource lock?
    if [[ -e "$football_logdir/lock.$res" ]] || [[ -e "$screener_logdir/lock.$res" ]] ; then
	echo "RESOURCE_LOCK $(date +%s) $(date) LOCAL $res LOCK" >> /dev/stderr
	echo 1
	return
    fi
    # 3. obey business hours
    if [[ "$business_hours" != "" ]]; then
	local date_spec="$(date +%u_%H)"
	if ! [[ "$date_spec" =~ ^($business_hours)$ ]]; then
	    echo "RESOURCE_LOCK $(date +%s) $(date) business_hours '$date_spec' !=~ '$business_hours' LOCK" >> /dev/stderr
	    echo 1
	    return
	fi
    fi
    # 4. Heuristics: tar processes indicate a running movespace or backup restore
    local something="$(remote "$res" "ps ax" | grep "/bin/tar ")"
    if [[ "$something" != "" ]]; then
	echo "RESOURCE_LOCK $(date +%s) $(date) resource $res is locked" >> /dev/stderr
	echo 1
    else
	echo 0
    fi
}

function cm3_resource_info
{
    local res="$1"
    local suffix="$2"

    if ! ping $ping_opts $res; then
	return
    fi
    echo "Show statistics for '$res$suffix'"
    local hyper="$(get_hyper $res)"
    [[ "$hyper" = "" ]] && return
    local mnt="$(cm3_get_mountpoint "$res")$suffix"
    local cmd="if mountpoint $mnt; then df -h $mnt; df -ih $mnt; fi"
    remote "$hyper" "$cmd" 1
    echo "---"
}

## cm3_stop_safeguard_cmd
# Workaround for a bug.
# Sometimes a systemd unit does not go away.
cm3_stop_safeguard_cmd="${cm3_stop_safeguard_cmd:-{ sleep 2; try=0; while (( try++ < 10 )) && systemctl show \$res.scope | grep ActiveState | grep =active; do systemctl stop \$res.scope; sleep 6; done; if mountpoint /vol/\$res; then umount /vol/\$res; fi; }}"

function cm3_resource_stop
{
    local host="$1"
    local res="$2"

    cm3_resource_info "$res"
    declare -g  downtime_begin
    [[ "$downtime_begin" = "" ]] && downtime_begin="$(date +%s)"
    echo "DOWNTIME BEGIN $(date)"
    ssh_hyper[$host]=""
    local safeguard="echo SEEMS_OK"
    if [[ "$cm3_stop_safeguard_cmd" != "" ]]; then
	local safeguard="$(eval "echo \"$cm3_stop_safeguard_cmd\"")"
	echo "Safeguard: $safeguard"
    fi
    # stop the whole stack
    remote "$host" "{ cm3 --stop $res || cm3 --stop $res; } && $safeguard; cm3 --stop $res"
}

function cm3_resource_stop_vm
{
    local hyper="$1"
    local res="$2"

    cm3_resource_info "$res"
    declare -g  downtime_begin
    [[ "$downtime_begin" = "" ]] && downtime_begin="$(date +%s)"
    echo "DOWNTIME BEGIN $(date)"
    ssh_hyper[$hyper]=""
    # stop only the vm, keep intermediate mounts etc
    remote "$hyper" "nodeagent vmstop $res"
}

function cm3_resource_stop_rest
{
    local hyper="$1"
    local primary="$2"
    local res="$3"

    # stop the rest of the stack
    remote "$hyper" "nodeagent stop $res"
    local mnt="$(cm3_get_mountpoint "$res")"
    remote "$hyper" "mountpoint $mnt && { umount -f $mnt ; exit \$?; } || true"
    cm3_resource_stop "$primary" "$res"
}

function cm3_resource_start
{
    local host="$1"
    local res="$2"

    remote "$host" "marsadm wait-cluster"
    remote "$host" "service clustermanager restart"
    sleep 2
    remote "$host" "marsadm primary --ignore-sync $res; marsadm primary $res"
    local safeguard="echo SEEMS_OK"
    if [[ "$cm3_stop_safeguard_cmd" != "" ]]; then
	local safeguard="$(eval "echo \"$cm3_stop_safeguard_cmd\"")"
	echo "Safeguard: $safeguard"
    fi
    remote "$host" "cm3 --stop $res; cm3 --start $res || { sleep 3; cm3 --stop $res; sleep 3; $safeguard; cm3 --stop $res; sleep 3; cm3 --start $res --ignore-status; } || false"
    echo "DOWNTIME END   $(date)"
    declare -g  downtime_begin
    declare -g  downtime_end="$(date +%s)"
    echo "DOWNTIME END $(date) ($(( downtime_end - downtime_begin )) s)"
    remote "$host" "if [[ -x /usr/sbin/nodeagent ]]; then /usr/sbin/nodeagent status; fi"
    cm3_resource_info "$res"
}

function cm3_resource_start_vm
{
    local hyper="$1"
    local res="$2"

    # start only the vm
    # precondition is that mounts etc are already present
    cm3_resource_info "$res"
    remote "$hyper" "nodeagent vmstart $res"
    declare -g  downtime_begin
    declare -g  downtime_end="$(date +%s)"
    echo "DOWNTIME END $(date) ($(( downtime_end - downtime_begin )) s)"
    remote "$hyper" "if [[ -x /usr/sbin/nodeagent ]]; then /usr/sbin/nodeagent status; fi"
}

## check_ping_rounds
# Number of pings to try before a container is assumed to
# not respond.
check_ping_rounds="${check_ping_rounds:-5}"

## additional_runstack
# Do an additional runstack after startup of the new container.
# In turn, this will only do something when source and target are
# different.
additional_runstack="${additional_runstack:-1}"

function cm3_resource_check
{
    local res="$1"
    local source="$2"
    local target="$3"
    local timeout="${4:-$check_ping_rounds}"

    local host="$res"
    echo "Checking whether $host is running...."
    while ! ping $ping_opts $host; do
	if (( timeout-- <= 0 )); then
	    echo "HOST $host DOES NOT PING!"
	    break
	fi
	sleep 3
    done
    cm3_resource_info "$res"
    if (( additional_runstack )) && [[ "$source" != "" ]] && [[ "$source" != "$target" ]]; then
	echo "Additional runstack source='$source' target='$target'"
	sleep 15
	(call_hook runstack "$source" "$target" "$res")
    fi
    echo "Checking $host via check_progs ...."
    sleep 15
    remote "$host" "check_progs -cvi" 1 || echo "ATTENTION SOMETHING DOES NOT WORK AT $host"
}

###########################################

# Workarounds for firewalling (transitional => TBD)

## workaround_firewall
# Documentation of technical debt for later generations:
# This is needed since July 2017. In the many years before, no firewalling
# was effective at the replication network, because it is a physically
# separate network from the rest of the networking infrastructure.
# An attacker would first need to gain root access to the _hypervisor_
# (not only to the LXC container and/or to KVM) before gaining access to
# those physical replication network interfaces.
# Since about that time, which is about the same time when the requirements
# for Container Football had been communicated, somebody introduced some
# unnecessary firewall rules, based on "security arguments".
# These arguments were however explicitly _not_ required by the _real_
# security responsible person, and explicitly _not_ recommended by him.
# Now the problem is that it is almost politically impossible to get
# rid of suchalike "security feature".
# Until the problem is resolved, Container Football requires
# the _entire_ local firewall to be _temporarily_ shut down in order to
# allow marsadm commands over ssh to work.
# Notice: this is _not_ increasing the general security in any way.
# LONGTERM solution / TODO: future versions of mars should no longer
# depend on ssh.
# Then this "feature" can be turned off.
workaround_firewall="${workaround_firewall:-1}"

function cm3_prepare_hosts
{
    local host_list="$1"

    if (( workaround_firewall )); then
	local host
	for host in $host_list; do
	    # Disabling is _necessary_ because of another security feature:
	    # Otherwise the firewall would be automatically restarted
	    # by a cron job.
	    local retry
	    for (( retry = 1; retry < 5; retry++ )); do
		remote "$host" "systemctl disable ui-firewalling.service || echo IGNORE"
		remote "$host" "service ui-firewalling stop || /etc/init.d/firewalling stop"
		if ! remote "$host" "iptables -L -n | grep DROP" 1; then
		    break
		fi
		echo "FIREWALL needs restart on $host" >> /dev/stderr
		sleep 10
	    done
	done
    fi
}

function cm3_finish_hosts
{
    local host_list="$1"

    if (( workaround_firewall )); then
	local host
	for host in $host_list; do
	    remote "$host" "systemctl enable ui-firewalling.service || echo IGNORE"
	    remote "$host" "service ui-firewalling restart || /etc/init.d/firewalling restart"
	done
    fi
}

###########################################

# Workarounds for ssh

function cm3_ssh_port
{
    local host="$1"
    local for_marsadm="${2:-0}"

    # ShaHoLin specific convention
    # trivially hard coded here => change here when necessary
    if [[ "$host" =~ icpu|infong ]]; then
	if (( for_marsadm )); then
	    echo "--ssh-port=24"
	else
	    echo "-p 24"
	fi
    fi
}

# Indirect ssh to containers only reachable via hypervisors

function cm3_check_port
{
    local host="$1"
    local port="${2:-22}"

    nc -z -w 3 $host $port
}

declare -g -A ssh_hyper=()

function cm3_ssh_indirect
{
    local host="$1"
    local cmd="$2"

    # these should be reachable directly
    if ! [[ "$host" =~ infong ]]; then
	return
    fi

    # already known?
    declare -g -A ssh_hyper
    local known="${ssh_hyper[$host]}"
    if [[ "$known" != "" ]]; then
	if [[ "$known" != "NONE" ]]; then
	    echo "$known:lxc-attach -n $host -- bash -c '${cmd//'/\\'}'"
	fi
	return
    fi

    # probe for direct reachability
    local port="$(cm3_ssh_port "$host" 2>/dev/null)"
    if cm3_check_port "$host" "${port##* }" 1>&2; then
	return
    fi

    # try to guess the right hypervisor
    local cluster="$(_get_cluster_name "$host" 2>/dev/null)"
    local hyper
    for hyper in $(_get_members "$cluster" 2>/dev/null); do
	[[ "$hyper" =~ icpu ]] || continue
	local hyper_port="$(cm3_ssh_port "$hyper" 2>/dev/null)"
	if cm3_check_port "$hyper" "${hyper_port##* }" 1>&2; then
	    local found="$(ssh $hyper_port $ssh_auth $ssh_opt "root@$hyper" "lxc-ls -1" | grep "^$host$")"
	    if [[ "$found" = "$host" ]]; then
		ssh_hyper[$host]="$hyper"
		echo "$hyper:lxc-attach -n $host -- bash -c '${cmd//'/\\'}'"
		return
	    fi
	fi
    done
    ssh_hyper[$host]="NONE"
}

###########################################

# Workarounds for ssh between different clusters

## ip_magic
# Similarly to workaround_firewall, this is needed since somebody
# introduced additional firewall rules also disabling sysadmin ssh
# connections at the _ordinary_ sysadmin network.
ip_magic="${ip_magic:-1}"

## do_split_cluster
# The current MARS branch 0.1a.y is not yet constructed for forming
# a BigCluster constisting of several thousands of machines.
# When a future version of mars0.1b.y (or 0.2.y) will allow this,
# this can be disabled.
# do_split_cluster >= 2 means that the resulting MARS clusters should
# not exceed these number of members, when possible.
do_split_cluster="${do_split_cluster:-2}"

function cm3_merge_cluster
{
    local source="$1"
    local target="$2"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return

    if remote "$target" "marsadm merge-cluster --ssh-port=24 $source" 1; then
	return
    fi
    local source_ip=""
    if (( ip_magic )); then
	# This MAGIC may be needed when mutual icpu / istore
	# ssh connects via hostnames are disallowed
	# by some network firewall rules.
	# Workaround by going down to the replication IPs.
	local source_ip="$(remote "$source" "marsadm lowlevel-ls-host-ips" | grep "$source" | sort -u | tail -1 | awk '{ print $2; }')"
	echo "Peer '$source' has IP '$source_ip'"
    fi
    if [[ "$source_ip" != "" ]] && \
	remote "$target" "marsadm merge-cluster --ssh-port=24 $source_ip" 1; then
	return
    fi
    # Workaround asymmetric firewalling
    echo "Trying swapped roles $source <=> $target"
    if remote "$source" "marsadm merge-cluster --ssh-port=24 $target" 1; then
	return
    fi
    if (( ip_magic )); then
	local target_ip="$(remote "$target" "marsadm lowlevel-ls-host-ips" | grep "$target" | sort -u | tail -1 | awk '{ print $2; }')"
	echo "Peer '$target' has IP '$target_ip'"
    fi
    if [[ "$target_ip" != "" ]] && \ 
	remote "$source" "marsadm merge-cluster --ssh-port=24 $target_ip" 1; then
	return
    fi
    fail "merge-cluster did not work on any ssh method"
}

function cm3_split_cluster
{
    local host_list="$1"

    local host
    # Check for senseless split-cluster
    if (( do_split_cluster > 1 )); then
	local max_members=$(
	    for host in $host_list; do
		remote "$host" "marsadm view-resource-members all" 1
	    done |\
		grep -o "\[[0-9]\+" |\
		grep -o "[0-9]\+" |\
		sort -n |\
		tail -1
	)
	echo "Maximum resource members at '$host_list' is '$max_members'"
	if (( max_members > do_split_cluster )); then
	    echo "EXCEEDING $do_split_cluster: actually running split-cluster would be senseless"
	    return
	fi
    fi
    if (( do_split_cluster )); then
	local ok=0
	local old_host
	local retry
	for (( retry=0; retry < 3; retry++ )); do
	    for host in $host_list; do
		sleep 5
		echo "Running split-cluster at '$host'"
		if remote "$host" "marsadm split-cluster --ssh-port=24" 1; then
		    ok=1
		    if (( do_split_cluster > 1 )); then
			# Ensure that nobody has > do_split_cluster members
			local host2
			for host2 in $host_list; do
			    local count="$(remote "$host2" "ls -l /mars/ips/ip-* | wc -l" 1)"
			    echo "Host '$host2' has '$count' cluster members"
			    if (( count > do_split_cluster )); then
				ok=0
			    fi
			done
		    fi
		    if (( ok )); then
			echo "Split-cluster seems OK at '$host'"
			break
		    fi
		fi
		old_host="$host"
		remote "$host" "marsadm wait-cluster" 1
	    done
	    (( ok )) && break
	    echo "Re-trying split-cluster once again at '$host_list'"
	    # try to fix asymmetric clusters by mutual re-merging
	    for host in $host_list; do
		sleep 5
		(
		    echo "Try re-merge $host <=> $old_host"
		    cm3_merge_cluster "$host" "$old_host"
		)
		old_host="$host"
		remote "$host" "marsadm wait-cluster" 1
	    done
	done
	if (( !ok )); then
	    warn "Please run 'marsadm split-cluster --ssh-port=24' by hand"
	fi
    fi
}

function cm3_join_resource
{
    local source="$1"
    local target="$2"
    local res="$3"
    local dev="$4"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return
    [[ "$res" = "" ]] && return

    local cmd="marsadm wait-cluster"
    cmd+="; marsadm join-resource --ssh-port=24 $res $dev"
    cmd+="|| { sleep 10; marsadm join-resource --force --ssh-port=24 $res $dev; }"
    remote "$target" "$cmd"
}

###########################################

# General checks

# This is deliberately not documented.
needed_marsadm="${needed_marsadm:-2.1 1.1}"
needed_mars="${needed_mars:-0.1stable49 0.1abeta0 mars0.1abeta0 0.1astable68}"
max_cluster_size="${max_cluster_size:-4}"
max_syncs="${max_syncs:-0}"

function check_needed
{
    local type="$1"
    local skip_prefix="$2"
    local actual="$3"
    local needed_list="$4"

    echo "$type actual version : $actual"
    echo "$type needed versions: $needed_list"
    local needed
    for needed in $needed_list; do
	local pa="$(echo "$actual" | grep -o "^$skip_prefix")"
	local pb="$(echo "$needed" | grep -o "^$skip_prefix")"
	#echo "pa='$pa' pb='$pb'"
	if [[ "$pa" != "$pb" ]]; then
	    #echo "prefix '$pa' != '$pb'"
	    continue
	fi
	local a="$(echo "$actual" | sed "s:^$skip_prefix::" | grep -o '[0-9.]\+' | head -1)"
	local b="$(echo "$needed" | sed "s:^$skip_prefix::" | grep -o '[0-9.]\+' | head -1)"
	#echo "skip_prefix='$skip_prefix' needed='$needed' a='$a' b='$b'"
	if [[ "$a" = "" ]] || [[ "$b" = "" ]]; then
	    continue
	fi
	if [[ "$b" =~ \. ]] && [[ "${a##*.}" != "${b##*.}" ]]; then
	    continue
	fi
	if (( $(echo "$a >= $b" | bc) )); then
	    echo "$type actual version '$actual' matches '$needed'"
	    return
	fi
    done
    fail "$type actual version '$actual' does not match one of '$needed_list'" "$illegal_status"
}

## forbidden_hosts
# Regex for excluding hostnames from any Football actions.
# The script will fail when some of these is encountered.
forbidden_hosts="${forbidden_hosts:-}"

## forbidden_flavours
# Regex for excluding flavours from any Football actions.
# The script will fail when some of these is encountered.
forbidden_flavours="${forbidden_flavours:-}"

## forbidden_bz_ids
# PROVISIONARY regex for excluding certain bz_ids from any Football actions.
# NOTICE: bz_ids are deprecated and should not be used in future
# (technical debts).
# The script will fail when some of these is encountered.
forbidden_bz_ids="${forbidden_bz_ids:-}"

## auto_two_phase
# When this is set, override the global migrate_two_phase parameter
# at runtime by ShaHoLin-specific checks
auto_two_phase="${auto_two_phase:-1}"

function cm3_check_host
{
    local host_list="$1"

    lock_hosts 1 "$host_list" ALL

    local host
    for host in $host_list; do
	echo "Checking host '$host'..."
	if [[ "$forbidden_hosts" != "" ]]; then
	    if [[ "$host" =~ $forbidden_hosts ]]; then
		fail "Host '$host' is forbidden by regex '$forbidden_hosts'" "$illegal_status"
	    fi
	fi
	# check that clustermw is working
	local cluster="$(_get_cluster_name "$host")"
	if [[ "$cluster" = "" ]]; then
	    fail "cannot determine cluster from host '$host'" "$illegal_status"
	fi
	echo "Host '$host' is on cluster '$cluster'"
	if [[ "$forbidden_flavours" != "" ]]; then
	    local flavour="$(call_hook get_flavour "$host" 2>/dev/null)"
	    echo "Host '$host' has flavour '$flavour'"
	    if [[ "$flavour" =~ $forbidden_flavours ]]; then
		fail "Flavour '$flavour' is forbidden by regex '$forbidden_flavours'" "$illegal_status"
	    fi
	fi
	if [[ "$forbidden_bz_ids" != "" ]]; then
	    local bz_id="$(call_hook get_bz_id "$host" 2>/dev/null)"
	    echo "Host '$host' has bz_id '$bz_id'"
	    if [[ "$bz_id" =~ $forbidden_bz_ids ]]; then
		fail "Bz_Id '$bz_id' is forbidden by regex '$forbidden_bz_ids'" "$illegal_status"
	    fi
	fi
	local serial="$(clustertool GET "/clusters/$cluster/properties/CLUSTERCONF_SERIAL")"
	if [[ "$serial" = "" ]]; then
	    fail "Suspected misconfiguration: cannot determine serial for cluster '$cluster'" "$illegal_status"
	fi
	echo "Cluster '$cluster' has serial '$serial'"
	local marsadm_version="$(remote "$host" "marsadm --version" | grep -o 'Version: [0-9.]*' | awk '{ print $2; }')"
	echo "Installed marsadm version at $host: '$marsadm_version'"
	check_needed "marsadm" "[0-9]\." "$marsadm_version" "$needed_marsadm"

	local mars_version="$(remote "$host" "cat /sys/module/mars/version" | awk '{ print $1; }' | cut -d- -f1 | sed 's/^mars//')"
	if [[ "$mars_version" = "" ]]; then
	    fail "MARS kernel module is not loaded at $host" "$illegal_status"
	fi
	check_needed "mars kernel module" "[a-z]*[0-9.]*[a-z]*" "$mars_version" "$needed_mars"
	if [[ "$(cm3_is_startable "$host" "" | tee -a /dev/stderr | tail -1)" != "1" ]]; then
	    fail "Clustermanager cm3 appears to not work at '$host'"
	fi
    done

    echo "Checking that max_cluster_size=$max_cluster_size will not be exceeded at $host_list"
    local new_cluster_size="$(
        for host in $host_list; do
            remote "$host" "marsadm lowlevel-ls-host-ips" 2>/dev/null
        done | sort -u | wc -l)"
    if (( new_cluster_size < 2 )); then
	fail "Implausible new cluster size $new_cluster_size" "$illegal_status"
    fi
    echo "New cluster size: $new_cluster_size"
    if (( new_cluster_size > max_cluster_size )); then
	fail "Cluster size limit $max_cluster_size will be exceeded, aborting." "$illegal_status"
    fi

    # Check that not too much syncs are already running
    local actual_syncs=0
    for host in $host_list; do
	local count="$(remote "$host" "marsadm view-sync-rest all" | grep '^[0-9]' | grep -v '^0' | wc -l)"
	echo "There are $count syncs running at $host"
	(( actual_syncs += count ))
    done
    echo "Total number of syncs: $actual_syncs"
    echo "Max   number of syncs: $max_syncs"
    if (( max_syncs > 0 && actual_syncs > max_syncs )); then
	fail "There are more than $max_syncs syncs running." "$illegal_status"
    fi

    # Workaround missing performance tuning which has not been rolled out for months now
    for host in $host_list; do
	local cmd="for i in \$(find /sys/devices/pci* -name nr_requests); do echo \"\$(cat \$i) \$i\"; echo 920 > \$i; done"
	remote "$host" "$cmd"
    done

    # Hack based on experience
    if (( auto_two_phase )); then
	local has_slow=0
	local has_fast=0
	local two_phase=1
	for host in $host_list; do
	    echo "Checking replication link speed of '$host'"
	    local cmd_slow="ethtool eth1 | grep 'Speed: 1000Mb/s'"
	    local cmd_fast="ethtool eth1 | grep 'Speed: 10000Mb/s'"
	    if remote "$host" "$cmd_slow" 1; then
		(( has_slow++ ))
	    elif remote "$host" "$cmd_fast" 1; then
		(( has_fast++ ))
	    else
		echo "Neither slow nor fast"
		two_phase=0
	    fi
	done
	if (( has_slow && has_fast )); then
	    echo "Setting migrate_two_phase $migrate_two_phase => $two_phase"
	    migrate_two_phase="$two_phase"
	fi
    fi
    lock_hosts
}

###########################################

# Mini infrastucture for access to clustermw

## clustertool_host
# URL prefix of the internal configuation database REST interface.
# Set this via *.preconf config files.
clustertool_host="${clustertool_host:-}"

## clustertool_user
# Username for clustertool access.
# By default, scans for a *.password file (see next option).
clustertool_user="${clustertool_user:-$(get_cred_file "*.password" | head -1 | sed 's:.*/::g' | cut -d. -f1)}"

echo "Using clustermw username: '$clustertool_user'" >> /dev/stderr

## clustertool_passwd_file
# Here you can supply the encrpted password.
# By default, a file $clustertool_user.password is used
# containing the encrypted password.
clustertool_passwd_file="${clustertool_passwd_file:-$(get_cred_file "$clustertool_user.password")}"

echo "Using clustermw password file: '$clustertool_passwd_file'" >> /dev/stderr

## clustertool_passwd
# Here you may override the password via config file.
# For security reasons, dont provide this at the command line.
clustertool_passwd="${clustertool_passwd:-$(< $clustertool_passwd_file)}" ||\
    echo "cannot read a password file *.password for clustermw: you MUST supply the credentials via default curl config files (see man page)"

function clustertool
{
    local op="${1:-GET}"
    local path="${2:-/clusters}"
    local content="$3"
    shift
    shift
    shift

    local inline_pw=""
    if [[ "clustertool_user" != "" ]]; then
	inline_pw="-u '$clustertool_user:${clustertool_passwd/\'/\\\'/}'"
    fi
    local cmd="curl -s $inline_pw -X \"$op\" \"$clustertool_host$path\""
    [[ "$content" != "" ]] && cmd+=" -d '${content//\'/\'}'"
    local arg
    for arg in "$@"; do
	cmd+=" \"$arg\""
    done
    echo "$cmd" | sed -u 's/\(curl .*\)-u *[^ ]*/\1/' >> /dev/stderr
    local output
    local retry
    for (( retry = 1; retry < 5; retry++ )); do
	output="$(eval "$cmd")"
	rc=$?
	if (( !rc )) && ! [[ "$output" =~ \"fault\"\ : ]]; then
	    echo "$output"
	    return 0
	fi
	echo "PROBLEM with clusterwm:" >> /dev/stderr
	echo "$output" >> /dev/stderr
	sleep 10
    done
    fail "failed REST command '$cmd'"
}

function cm3_clustertool
{
    shift
    local op="${1:-GET}"
    local path="${2:-/clusters}"
    shift 2
    clustertool "$op" "$path" "" "$@"
}

function _get_cluster_name
{
    local host="$1"

    local url="/vms/$host.schlund.de"
    [[ "$host" =~ icpu ]] && url="/nodes/$host.schlund.de"
    [[ "$host" =~ istore ]] && url="/storagehosts/$host.schlund.de"
    clustertool GET "$url" |\
	json_pp |\
	grep -o '"cluster" : ".*"' |\
	cut -d: -f2 |\
	sed 's/[" ]//g' |\
	sort -u
}

function _get_segment
{
    local cluster="$1"

    local url="/clusters/$cluster"
    clustertool GET "$url" |\
	json_pp |\
	grep '"segment"' |\
	cut -d: -f2 |\
	sed 's/[ ",]//g'
}

function _get_members
{
    local cluster="$1"

    local url="/clusters/$cluster"
    clustertool GET "$url" |\
	json_pp |\
	grep -o '[-a-z0-9]\+.schlund.de' |\
	cut -d. -f1 |\
	sort -u |\
	grep -v infong
}

function cm3_get_location
{
    local host="$1"

    local url="/nodes/$host.schlund.de"
    if [[ "$host" =~ infong ]]; then
	url="/vms/$host.schlund.de"
    fi
    clustertool GET "$url" |\
	json_pp |\
	grep "location.*:" |\
	grep -o '".*"' |\
	sed 's/"//g' |\
	sed 's/^.*: *//'
}

function cm3_get_flavour
{
    local host="$1"

    local url="/nodes/$host.schlund.de"
    if [[ "$host" =~ infong ]]; then
	url="/vms/$host.schlund.de"
    fi
    clustertool GET "$url" |\
	json_pp |\
	grep flavour |\
	grep -o '".*"' |\
	sed 's/"//g' |\
	sed 's/^.*: *//'
}

function cm3_get_bz_id
{
    local host="$1"

    local url="/nodes/$host.schlund.de"
    if [[ "$host" =~ infong ]]; then
	url="/vms/$host.schlund.de"
    fi
    clustertool GET "$url" |\
	json_pp |\
	grep bz_id |\
	grep -o '".*"' |\
	sed 's/"//g' |\
	sed 's/^.*: *//'
}

function cm3_get_hvt_id
{
    local host="$1"

    local url="/nodes/$host.schlund.de"
    if [[ "$host" =~ infong ]]; then
	url="/vms/$host.schlund.de"
    fi
    clustertool GET "$url" |\
	json_pp |\
	grep hvt_id |\
	grep -o '".*"' |\
	sed 's/"//g' |\
	sed 's/^.*: *//'
}

function cm3_get_hwclass_id
{
    local host="$1"

    local url="/nodes/$host.schlund.de"
    if [[ "$host" =~ infong ]]; then
	url="/vms/$host.schlund.de"
    fi
    clustertool GET "$url" |\
	json_pp |\
	grep hwclass_id |\
	grep -o '".*"' |\
	sed 's/"//g' |\
	sed 's/^.*: *//'
}

###########################################

# Migration operation: move cm3 config from old cluster to a new cluster

## do_migrate
# Keep this enabled. Only disable for testing.
do_migrate="${do_migrate:-1}" # must be enabled; disable for dry-run testing

## always_migrate
# Only use for testing, or for special situation.
# This skip the test whether the resource has already migration.
always_migrate="${always_migrate:-0}" # only enable for testing

## check_segments
# 0 = disabled
# 1 = only display the segment names
# 2 = check for equality
# WORKAROUND, potentially harmful when used inadequately.
# The historical physical segment borders need to be removed for
# Container Football.
# Unfortunately, the subproject aiming to accomplish this did not
# proceed for one year now. In the meantime, Container Football can
# be only played within the ancient segment borders.
# After this big impediment is eventually resolved, this option
# should be switched off.
check_segments="${check_segments:-1}"

function _check_migrate
{
    local source="$1"
    local target="$2"
    local res="$3"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return
    [[ "$res" = "" ]] && return

    local source_cluster="$(_get_cluster_name "$source")" || fail "cannot get source_cluster" "$illegal_status"
    local target_cluster="$(_get_cluster_name "$target")" || fail "cannot get target_cluster" "$illegal_status"

    echo "source_cluster='$source_cluster'"
    echo "target_cluster='$target_cluster'"

    [[ "$source_cluster" = "" ]] && fail "cm3 source cluster is undefined" "$illegal_status"
    [[ "$target_cluster" = "" ]] && fail "cm3 target cluster is undefined" "$illegal_status"

    if [[ "$source_cluster" != "$target_cluster" ]]; then
	if (( check_segments )); then
	    # At the moment, cross-segment migrations won't work.
	    # TBD.
	    local source_segment="$(_get_segment "$source_cluster")" || fail "cannot get source_segment" "$illegal_status"
	    local target_segment="$(_get_segment "$target_cluster")" || fail "cannot get target_segment" "$illegal_status"
	    echo "source_segment='$source_segment'"
	    echo "target_segment='$target_segment'"
	    if (( check_segments > 1 )); then
		[[ "$source_segment" = "" ]] && fail "cannot determine source segment" "$illegal_status"
		[[ "$target_segment" = "" ]] && fail "cannot determine target segment" "$illegal_status"
		[[ "$source_segment" != "$target_segment" ]] && fail "source_segment '$source_segment' != target_segment '$target_segment'" "$illegal_status"
	    fi
	fi
    fi

}

function cm3_update_cm3_config
{
    local host_list="$1"

    echo "UPDATE cm3 config on " $host_list
    echo ""

    local update_host_list="$host_list"
    local host
    local i
    for (( i = 0; i < 3; i++ )); do
	local new_host_list=""
	local status=0
	sleep 10
	for host in $update_host_list; do
	    remote "$host" "service clustermanager restart"
	done
	sleep 5
	for host in $update_host_list; do
	    timeout_cmd "remote '$host' 'cm3 --update --force'"
	    local rc=$?
	    (( status |= rc ))
	    (( rc )) && new_host_list+=" $host"
	done
	(( !status )) && break
	echo "RESTARTING cm3 update on $new_host_list"
	update_host_list="$new_host_list"
    done
    sleep 5
    for host in $host_list; do
	remote "$host" "service clustermanager restart"
    done
    sleep 3
    for host in $host_list; do
	remote "$host" "update-motd || echo IGNORE"
    done
}

function cm3_is_startable
{
    local host="$1"
    local res="$2"

    if [[ "$res" = "" ]]; then
	# Check whether the clustermanager works at all...
	if remote "$host" "cm3 -us" 1; then
	    echo "1"
	else
	    echo "0"
	fi
	return
    fi
    if (remote "$host" "cm3 -us") | grep -q " $res "; then
	echo "1"
    else
	echo "0"
    fi
}

function cm3_check_handover
{
    local source="$1"
    local target="$2"
    local res="$3"

    local source_cluster="$(_get_cluster_name "$source")" || fail "cannot get source_cluster" "$illegal_status"
    local target_cluster="$(_get_cluster_name "$target")" || fail "cannot get target_cluster" "$illegal_status"
    echo "Source '$source' is at cluster '$source_cluster'"
    echo "Target '$target' is at cluster '$target_cluster'"
    [[ "$source_cluster" = "" ]] && fail "Cannot determine source cluster" "$illegal_status"
    [[ "$target_cluster" = "" ]] && fail "Cannot determine target cluster" "$illegal_status"
    if [[ "$source_cluster" != "$target_cluster" ]]; then
	fail "Cannot handover from '$source' to '$target': cluster names are different" "$illegal_status"
    fi
    if [[ "$(cm3_is_startable "$target" "$res")" != "1" ]]; then
	fail "According to 'cm3 -us', resource '$res' is not startable at '$target'"
    fi
}

## enable_mod_deflate
# Internal, for support.
enable_mod_deflate="${enable_mod_deflate:-1}"

## enable_segment_move
# Seems to be needed by some other tooling.
enable_segment_move="${enable_segment_move:-1}"

## override_hwclass_id
# When necessary, override this from $include_dir/plugins/*.conf
override_hwclass_id="${override_hwclass_id:-}" # typically 25007

## override_hvt_id
# When necessary, override this from $include_dir/plugins/*.conf
override_hvt_id="${override_hvt_id:-}" # typically 8057 or 8059

## override_overrides
# When this is set and other override_* variables are not set,
# then try to _guess_ some values.
# No guarantees for correctness either.
override_overrides=${override_overrides:-1}

function cm3_migrate_cm3_config
{
    local source="$1"
    local target="$2"
    local res="$3"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return
    [[ "$res" = "" ]] && return

    local source_cluster="$(_get_cluster_name "$source")" || fail "cannot get source_cluster" "$illegal_status"
    local target_cluster="$(_get_cluster_name "$target")" || fail "cannot get target_cluster" "$illegal_status"
    if (( always_migrate )) || [[ "$source_cluster" != "$target_cluster" ]]; then
	echo "Moving config from cluster '$source_cluster' to cluster '$target_cluster'"

	local backup=""
	if [[ "$football_backup_dir" != "" ]]; then
	    local backup="$football_backup_dir/json-backup.$start_stamp"
	    mkdir -p $backup
	fi

	local status_url="/vms/$res.schlund.de"
	clustertool GET "$status_url" |\
	    log "$backup" "$res.old.raw.json" |\
	    json_pp |\
	    log "$backup" "$res.old.pp.json"

	if ! [[ -s "$backup/$res.old.raw.json" ]]; then
	    fail "cluster config for vm '$res' is empty" "$illegal_status"
	fi

	local old_url="/clusters/$source_cluster/vms/$res.schlund.de"
	local new_url="/clusters/$target_cluster/vms/$res.schlund.de"
	echo clustertool DELETE "$old_url"
	(( do_migrate )) && clustertool DELETE "$old_url"
	echo clustertool PUT    "$new_url"
	(( do_migrate )) && clustertool PUT    "$new_url"

	clustertool GET "$status_url" |\
	    log "$backup" "$res.new.raw.json" |\
	    json_pp |\
	    log "$backup" "$res.new.pp.json"

	echo "--------------------- diff old => new ------------------"
	diff -ui $backup/$res.old.pp.json $backup/$res.new.pp.json
	echo ""
	# Optional actions
	if (( enable_mod_deflate )); then
	    local url="/vms/$res.schlund.de/properties"
	    local old_val="$(clustertool GET "$url")"
	    echo "OLD properties:"
	    echo "$old_val" | json_pp
	    local update_url="$url/ENABLE_MOD_DEFLATE"
	    (clustertool PUT "$update_url" yes || echo IGNORE)
	    local new_val="$(clustertool GET "$url")"
	    echo "NEW properties:"
	    echo "$new_val" | json_pp
	fi
	if (( enable_segment_move )); then
	    local source_segment="$(_get_segment "$source_cluster")" || fail "cannot get source_segment" "$illegal_status"
	    local target_segment="$(_get_segment "$target_cluster")" || fail "cannot get target_segment" "$illegal_status"
	    echo "source_segment='$source_segment'"
	    echo "target_segment='$target_segment'"
	    if [[ "$source_segment" != "" ]] && [[ "$target_segment" != "" ]] ; then
		local source_url="/segments/$source_segment/vms/$res.schlund.de"
		local target_url="/segments/$target_segment/vms/$res.schlund.de"
		echo clustertool GET "$source_url"
		(clustertool GET "$source_url") |\
		    log "$backup" "$res.segm.raw.json" |\
		    json_pp |\
		    log "$backup" "$res.segm.pp.json"
		if [[ -s $backup/$res.segm.raw.json ]]; then
		    echo clustertool DELETE "$source_url"
		    (clustertool DELETE "$source_url" || echo IGNORE)
		    echo clustertool PUT "$target_url" "$(< $backup/$res.segm.raw.json)"
		    (clustertool PUT "$target_url" "$(< $backup/$res.segm.raw.json)" || echo IGNORE)
		fi
	    fi
	fi
	echo ""
	# Overrides of *_id
	if (( override_overrides )); then
	    if [[ "$location" =~ ^de\. ]]; then
		if [[ "$override_hvt_id" = "" ]] ; then
		    override_hvt_id=8047
		    echo "Override hvt_id=$override_hvt_id"
		fi
	    elif [[ "$location" =~ ^us\. ]]; then
		if [[ "$override_hvt_id" = "" ]] ; then
		    override_hvt_id=8059
		    echo "Override hvt_id=$override_hvt_id"
		fi
	    fi
	    if [[ "$override_hwclass_id" = "" ]]; then
		override_hwclass_id=25007
		echo "Override hwclass_id=$override_hwclass_id"
	    fi
	fi
	local override=""
	if [[ "$override_hwclass_id" != "" ]]; then
	    override=+"\"hwclass_id\" : \"$override_hwclass_id\", "
	fi
	if [[ "$override_hvt_id" != "" ]] ; then
	    override+"\"hvt_id\" : \"$override_hvt_id\", "
	fi
	if [[ "$override" != "" ]]; then
	    local target_url="/vms/$res.schlund.de"
	    local arg="{ $override }"
	    echo clustertool PUT "$target_url" "$arg"
	    (clustertool PUT "$target_url" "$arg" || echo IGNORE)
	    echo ""
	fi
	# Tell the world that something has changed
	(clustertool PUT "/clusters/$source_cluster/properties/CLUSTERCONF_SERIAL") ||\
	    echo IGNORE
	(clustertool PUT "/clusters/$target_cluster/properties/CLUSTERCONF_SERIAL") ||\
	    echo IGNORE
	echo ""

	section "Update cm3 configs"

	# Determine all hosts where a clustermanagerd _should_ be running.
	# Unfortunately, parsing the "storagehost" part will not work for standalone icpus.
	# Use a provisionary heuristics here, based on naming conventions.
	local total_list="$(
	{
	    echo "$source"
	    echo "$target"
	    for cluster in $source_cluster $target_cluster; do
		if ! _get_members $cluster | grep istore; then
		    _get_members $cluster
		fi
	    done
	} |\
		sort -u)"
	cm3_update_cm3_config "$total_list"
	(call_hook runstack "$source" "$target" "$res")
	(call_hook dastool  "$source" "$target" "$res")
	(call_hook update_action "$res")
	echo "Migrated from '$source_cluster' to '$target_cluster'"
    else
	echo "Source and target clusters are equal: '$source_cluster'"
	echo "Nothing to do."
    fi
}

function cm3_check_migrate
{
    local source="$1"
    local target="$2"
    local res="$3"

    _check_migrate "$source" "$target" "$res"
}

function cm3_determine_old_replicas
{
    local primary="$1"
    local res="$2"

    local primary_cluster="$(_get_cluster_name "$primary")"
    local secondary_list="$(remote "$primary" "marsadm view-resource-members $res" | { grep -v "^$primary$" || true; })" || fail "cannot determine secondary_list" "$illegal_status"
    local host
    for host in $secondary_list; do
	local cluster="$(_get_cluster_name "$host")"
	if [[ "$cluster" != "$primary_cluster" ]]; then
	    echo "FOREIGN:$host"
	fi
    done
}

function cm3_determine_new_replicas
{
    local primary="$1"
    local res="$2"

    local primary_cluster="$(_get_cluster_name "$primary")"
    local secondary_list="$(remote "$primary" "marsadm view-resource-members $res" | { grep -v "^$primary$" || true; })" || fail "cannot determine secondary_list" "$illegal_status"
    local host
    for host in $primary $secondary_list; do
	local cluster="$(_get_cluster_name "$host")"
	if [[ "$cluster" = "$primary_cluster" ]]; then
	    echo "FOREIGN:$host"
	fi
    done
}

###########################################
# Local quota transfer for LXC containers.
# Problem: kuid_t implies that dump and restore is USER_NS specific,
# at least with currently used kernel + userspace tool versions.

function _get_kunden_dev
{
    local lv_name="$1"

    remote "$lv_name" "df /kunden/homepages/ | grep '^/dev' | head -1 | awk '{ print \$1; }'"
}

function cm3_save_local_quota
{
    local hyper="$1"
    local lv_name="$2"

    if (( do_quota >= 2 )); then
	section "Local xfs quota dump"

	local dumpfile="$xfs_dump_dir/xfs_dump.local.$hyper.$lv_name"
	local local_dev="/dev/mars/$lv_name"
	local store="$(get_store "$lv_name")"
	echo "store='$store'"
	if [[ "$store" != "$hyper" ]]; then
	    local_dev="$(_get_kunden_dev "$lv_name")"
	    if ! [[ "$local_dev" =~ /dev/ ]]; then
		# last resort fallback, try to preserve the data for hand repair
		echo "WARNING: local device is '$local_dev'" >> /dev/stderr
		echo "WARNING: cannot determine local device for /kunden/homepages on $lv_name" >> /dev/stderr
		local_dev="/kunden/homepages"
	    fi
	fi
	echo "local_dev='$local_dev'"

	remote "$lv_name" "$xfs_dump $local_dev" > $dumpfile
	ls -l $dumpfile
	wc -l $dumpfile
    fi
}

function cm3_restore_local_quota
{
    local hyper="$1"
    local lv_name="$2"

    if (( do_quota >= 2 )); then
	local dumpfile="$xfs_dump_dir/xfs_dump.local.$hyper.$lv_name"

	section "Local xfs quota restore"

	if [[ -s "$dumpfile" ]]; then
	    local max_rounds=$check_ping_rounds
	    while ! ping $ping_opts "$lv_name"; do
		if (( max_rounds-- < 0 )); then
		    (( !skip_resource_ping )) && fail "host $lv_name does not ping"
		    warn "You allowed skipping of resource ping."
		    warn "cannot restore the quota at $lv_name"
		    return
		fi
		sleep 10
	    done
	    sleep 10

	    local local_dev="/dev/mars/$lv_name"
	    local store="$(get_store "$lv_name")"
	    echo "store='$store'"
	    if [[ "$store" != "$hyper" ]]; then
		local_dev="$(_get_kunden_dev "$lv_name")"
		if ! [[ "$local_dev" =~ /dev/ ]]; then
		    echo "Sorry, cannot determine local device for /kunden/homepages on $lv_name" >> /dev/stderr
		    return 0
		fi
	    fi
	    echo "local_dev='$local_dev'"

	    {
		echo "fs = $local_dev"
		grep -v "^fs =" < $dumpfile
	    } > $dumpfile.new
	    ls -l $dumpfile.new
	    wc -l $dumpfile.new

	    local max_rounds=10
	    while ! remote "$lv_name" "$xfs_restore $local_dev" 1 < $dumpfile.new; do
		(( max_rounds-- < 0 )) && fail "host $lv_name does not ping"
		sleep 10
	    done
	else
	    echo "LOCAL $lv_name QUOTA IS EMPTY"
	fi
    fi
}


###########################################

# Hooks for shrinking

## iqn_base and iet_type and iscsi_eth and iscsi_tid
# Workaround: this is needed for _dynamic_ generation of iSCSI sessions
# bypassing the ordinary ones as automatically generated by the
# cm3 cluster manager (only at the old istore architecture).
# Notice: not needed for regular operations, only for testing.
# Normally, you dont want to shrink over a _shared_ 1MBit iSCSI line.
iqn_base="${iqn_base:-iqn.2000-01.info.test:test}"
iet_type="${iet_type:-blockio}"
iscsi_eth="${iscsi_eth:-eth1}"
iscsi_tid="${iscsi_tid:-4711}"

function new_tid
{
    local iqn="$1"
    local store="$2"

    declare -g iscsi_tid

    local old_tids="$(remote "$store" "cat /proc/net/iet/volume /proc/net/iet/session" 1 | grep -o 'tid:[0-9]\+' | cut -d: -f2 | sort -u)"
    echo "old tids: " $old_tids >> /dev/stderr
    while echo $old_tids | grep "$iscsi_tid" 1>&2; do
	(( iscsi_tid++ ))
    done
    echo "iSCSI IQN '$iqn' has new tid '$iscsi_tid'" >> /dev/stderr
    echo "$iscsi_tid"
}

function cm3_disconnect
{
    local store="$1"
    local res="$2"

    local iqn="$iqn_base.$res.tmp"

    # safeguarding: retrieve any matching runtime session
    local hyper
    for hyper in $(remote "$store" "grep -A1 'name:$iqn' < /proc/net/iet/session | grep 'initiator:' | grep -o 'icpu[0-9]\+'" 1); do
	remote "$hyper" "iscsiadm -m node -T $iqn -u || echo IGNORE iSCSI initiator logout"
    done
    # safeguarding: retrieve any matching tid
    local tid
    for tid in $(remote "$store" "grep 'name:$iqn' < /proc/net/iet/volume | cut -d' ' -f1 | cut -d: -f2" 1); do
	echo "KILLING old tid '$tid' for iqn '$iqn' on '$store'"
	remote "$store" "ietadm --op delete --tid=$tid || echo IGNORE iSCSI target deletion"
    done
}

function cm3_connect
{
    local store="$1"
    local hyper="$2"
    local res="$3"

    # for safety, kill any old session
    cm3_disconnect "$store" "$res"

    local vg_name="$(get_vg "$store")" || fail "cannot determine VG for host '$store'" "$illegal_status"
    local dev="/dev/$vg_name/$res"
    local iqn="$iqn_base.$res.tmp"
    local iscsi_ip="$(remote "$store" "ifconfig $iscsi_eth" | grep "inet addr:" | cut -d: -f2 | awk '{print $1;}')"
    echo "using iscsi IP '$iscsi_ip'"

    # saftey check
    remote "$hyper" "ping $ping_opts $iscsi_ip"

    # step 1: setup stone-aged IET on storage node
    local tid="$(new_tid "$iqn" "$store")"
    remote "$store" "ietadm --op new --tid=$tid --params=Name=$iqn"
    remote "$store" "ietadm --op new --tid=$tid --lun=0 --params=Path=$dev"
    sleep 2

    # step2: import iSCSI on hypervisor
    remote "$hyper" "iscsiadm -m discovery -p $iscsi_ip --type sendtargets"
    tmp_list="/tmp/devlist.$$"
    register_unlink "$tmp_list"
    remote "$hyper" "ls /dev/sd?" > $tmp_list
    remote "$hyper" "iscsiadm -m node -p $iscsi_ip -T $iqn -l"
    while true; do
	sleep 3
	local new_dev="$(remote "$hyper" "ls /dev/sd?" | diff -u $tmp_list - | grep '^+/' | cut -c2-)"
	[[ -n "$new_dev" ]] && break
    done
    rm -f $tmp_list
    unregister_unlink "$tmp_list"
    echo "NEW_DEV:$new_dev"
}

###########################################

# Hooks for extending of XFS

function cm3_extend_iscsi
{
    local hyper="$1"

    remote "$hyper" "iscsiadm -m session -R"
}

###########################################

# Internal interface to Monitis
# and other internal communication

## monitis_downtime_script
# ShaHoLin-internal
monitis_downtime_script="${monitis_downtime_script:-}"

## monitis_downtime_duration
# ShaHoLin-internal
monitis_downtime_duration="${monitis_downtime_duration:-60}" # Minutes

## orwell_downtime_script
# ShaHoLin-internal
orwell_downtime_script="${orwell_downtime_script:-}"

## orwell_tz
# Deal with differences in clock timezones.
orwell_tz="${orwell_tz:-Europe/Berlin}"

## orwell_downtime_duration
# ShaHoLin-internal
orwell_downtime_duration="${orwell_downtime_duration:-20}" # Minutes

## orwell_workaround_sleep
# Workaround for a race condition in Orwell.
# Try to ensure that another check has been executed before
# the downtime is removed.
# 0 = dont remove the downtime at all.
orwell_workaround_sleep="${orwell_workaround_sleep:-300}" # Seconds

function cm3_want_downtime
{
    local resource="$1"
    local down="${2:-0}"
    local comment="${3:-Tetris2 ${operation/+/-} $ticket}"

    call_hook update_ticket "" "downtime.$down"

    if [[ "$monitis_downtime_script" = "" ]]; then
	return
    fi
    local cmd=""
    if (( down )); then
	local now="$(date "+%Y%m%d-%H:%M")"
	cmd="$monitis_downtime_script set --start $now --duration $monitis_downtime_duration $resource.schlund.de"
    else
	cmd="$monitis_downtime_script get $resource.schlund.de"
    fi
    echo "Calling Monitis script: $cmd"
    ($cmd)
    echo "Script rc=$?"

    if (( down )); then
	local now="$(date +%s)"
	local cmd=""
	if [[ "$orwell_tz" != "" ]]; then
	    cmd="TZ=\"$orwell_tz\" "
	fi
	cmd+="date --date=@\$now \"+%d/%m/%Y %H:%M\""
	echo "Date command: '$cmd'"
	local start_time="$(eval "$cmd")"
	echo "Orwell-specific start time is '$start_time'"
	(( now += orwell_downtime_duration * 60 ))
	local end_time="$(eval "$cmd")"
	echo "Orwell-specific end   time is '$end_time'"
	cmd="$orwell_downtime_script hdowntime_add $resource.schlund.de '$start_time' '$end_time' '${comment//_/-}'"
	if [[ "$orwell_downtime_script" != "" ]]; then
	    echo "Calling Orwell script: $cmd"
	    ($cmd)
	    echo "Script rc=$?"
	    register_cleanup "orwell" "call_hook want_downtime $res 0"
	fi
    else
	cmd="$orwell_downtime_script hdowntime_list"
	if [[ "$orwell_downtime_script" != "" ]]; then
	    unregister_cleanup "orwell"
	    echo "Calling Orwell script: $cmd"
	    local result="$($cmd)"
	    local rc=$?
	    echo "Script rc=$rc"
	    echo "$result"
	    local id_list="$(echo "$result" | grep " $resource.schlund.de" | grep -o "^[0-9]\+")"
	    # Do the workaround sleep only when there is no failure.
	    # Otherwise Orwell is re-enabled ASAP.
	    if (( orwell_workaround_sleep > 0 )) &&\
		(( !exit_status )) &&\
		[[ "$id_list" != "" ]]; then
		echo "Workaround: sleeping for '$orwell_workaround_sleep' seconds"
		sleep $orwell_workaround_sleep
	    fi
	    local id
	    for id in $id_list; do
		echo "Canceling downtime id '$id'"
		cmd="$orwell_downtime_script hdowntime_delete $id"
		echo "Calling Orwell script: $cmd"
		($cmd)
		echo "Script rc=$?"
	    done
	fi
    fi
}

## shaholin_customer_report_cmd
# Action script when the hardware has improved.
shaholin_customer_report_cmd="${shaholin_customer_report_cmd:-}"

## shaholin_min_cpus and shaholin_dst_cpus
shaholin_src_cpus="${shaholin_src_cpus:-4}"
shaholin_dst_cpus="${shaholin_dst_cpus:-32}"

## ip_renumber_cmd
# Cross-call with another independent project.
ip_renumber_cmd="${ip_renumber_cmd:-}"

function cm3_football_start
{
    if [[ "$res" = "" ]]; then
	return
    fi
    local cpu_count="$(get_cpu_count "$res")"
    echo "Host '$res' has $cpu_count CPUs"
    if (( cpu_count > 0 && cpu_count <= shaholin_src_cpus )); then
	echo "Resource '$res' is on old hardware"
	register_unlink "$football_logdir/shaholin-cpus.$res"
	echo "$cpu_count" > $football_logdir/shaholin-cpus.$res
    fi
    if [[ "$ip_renumber_cmd" != "" ]]; then
	local cmd="$ip_renumber_cmd $res"
	echo "Calling IP renumbering script '$cmd'"
	($cmd)
	echo "Script rc='$?'"
    fi
}

## shaholin_finished_log
# ShaHoLin-specific logfile, reporting _only_ successful completion
# of an action.
shaholin_finished_log="${shaholin_finished_log:-$football_logdir/shaholin-finished.log}"

shaholin_finished_called=0

function cm3_football_finished
{
    local status="$1"
    shift
    local txt="$(echo "$@")"

    if [[ "$res" != "" ]] && [[ -r $football_logdir/shaholin-cpus.$res ]]; then
	local cpu_count="$(get_cpu_count "$res")"
	echo "Host '$res' has $cpu_count CPUs"
	if (( cpu_count >= shaholin_dst_cpus )); then
	    echo "Resource '$res' is on new hardware"
	    echo "$res $(date +%s) $(date)" >> $football_logdir/shaholin-migrations.log
	    if [[ "$shaholin_customer_report_cmd" != "" ]]; then
		local cmd="$(eval "echo \"$shaholin_customer_report_cmd \${res}.schlund.de \"")"
		echo "Running command '$cmd'"
		(eval "$cmd")
	    fi
	    rm -f $football_logdir/shaholin-cpus.$res
	    unregister_unlink "$football_logdir/shaholin-cpus.$res"
	fi
    fi

    if [[ "$shaholin_finished_log" = "" ]]; then
	return
    fi
    if (( status )); then
	return
    fi
    if ! [[ "$txt" =~ migrate ]]; then
	return
    fi
    if (( !shaholin_finished_called++ )); then
	echo "$txt" >> "$shaholin_finished_log"
    fi
}

## update_cmd
# OPTIONAL: specific action script with parameters.
update_cmd="${update_cmd:-}"

## update_host
# To be provided in a *.conf or *.preconf file.
update_host="${update_host:-}"

## parse_ticket
# Regex for identifying tickets from script outputs or arguments
parse_ticket="${parse_ticket:-TECCM-[0-9]\+}"

## prefer_parsed_ticket
# Workaround bugs from getting inconsistent ticket IDs from different sources.
prefer_parsed_ticket="${prefer_parsed_ticket:-0}"

## translate_db_state
# Whether to use the following mapping definitions.
translate_db_state="${translate_db_state:-0}"

## db_state_*
# Map logical names to the ones in the database.
db_state_init="${db_state_init:-}"
db_state_prepare="${db_state_prepare:-}"
db_state_finish="${db_state_finish:-}"
db_state_cleanup="${db_state_cleanup:-}"
db_state_done="${db_state_done:-}"

## use_type_for_ticket
# Internal ticketing convention.
use_type_for_ticket="${use_type_for_ticket:-1}"

# avoid multiple calls
declare -g -A db_called=()

function cm3_tell_action
{
    local db_type="$1"
    local db_resource="$res"
    local db_change="$ticket"
    local db_srcCluster="$(_get_cluster_name "$db_resource" 2>/dev/null)"
    local db_dstCluster="$(_get_cluster_name "$target_primary" 2>/dev/null)"
    local db_state="$2"

    if [[ "$db_srcCluster" = "" ]]; then
	db_srcCluster="$(_get_cluster_name "$primary" 2>/dev/null)"
    fi
    if [[ "$db_dstCluster" = "" ]]; then
	db_dstCluster="$db_srcCluster"
    fi

    # Translate to a different wording
    local var="db_state_$db_state"
    local val="$(eval echo "\${$var}")"
    echo "Translated state for action '$db_type': $var='$val'"
    if (( translate_db_state )); then
	if [[ "$val" = "" ]]; then
	    echo "No translation, ignoring this action"
	    return
	fi
	echo "Using translated state name '$val'"
	db_state="$val"
    fi

    # Check for doubled calls (e.g. might result from translations)
    local index="${db_type}_${db_state}"
    if (( db_called[$index] )); then
	echo "Already called: '$index'"
	return
    fi
    db_called[$index]=1

    # DB EfficiencyReport update
    if [[ "$update_host" = "" ]] || [[ "$update_cmd" = "" ]]; then
	echo "update_host='$update_host' update_cmd='$update_cmd'"
    else
	local cmd="$(eval echo "$update_cmd")"
	echo "Action on '$update_host': '$cmd'"

	local tmp_output="/tmp/output.$$"
	register_unlink "$tmp_output"
	(
	    remote "$update_host" "$cmd" 1
	    echo "Action rc=$?"
	) 2>&1 | tee $tmp_output
	local parsed="$(grep -o -e "$parse_ticket" < $tmp_output)"
	echo "parsed='$parsed'"
	unregister_unlink "$tmp_output"
    fi

    # Ticket update from plugin/football-ticket ....
    echo "original ticket='$ticket'"
    if [[ "$ticket" = "" ]] && [[ "$parsed" != "" ]] && (( prefer_parsed_ticket )); then
	ticket="$parsed"
	echo "parsed ticket='$ticket'"
    fi
    if [[ "$ticket" = "" ]]; then
	call_hook pre_init
	echo "pre_init ticket='$ticket'"
    fi
    if [[ "$ticket" = "" ]] && [[ "$parsed" != "" ]]; then
	ticket="$parsed"
	echo "Last resort: use parsed ticket='$ticket'"
    fi
    if [[ "$ticket" != "" ]]; then
	local msg="SCREENER_LOCATION=$location,$ticket"
	echo "$msg"
    fi
    local phase="$operation"
    if (( use_type_for_ticket )); then
	phase="$db_type"
    fi
    echo "Using ticket_phase='$phase'"
    call_hook update_ticket "$phase" "action.$db_type.$db_state"
    call_hook update_ticket "$phase" "action.$db_type"
    call_hook update_ticket "$phase" "action.$db_state"
    call_hook update_ticket "$phase" "action"

    return 0
}

###########################################

orig_location=""

function cm3_determine_variables
{
    location="$(call_hook get_location "$hyper" 2>/dev/null)"
    echo "SCREENER_LOCATION=$location"
    orig_location="$location"
    echo "Determined the following           LOCATION: \"$location\""
    res_flavour="$(call_hook get_flavour "$res" 2>/dev/null)"
    echo "Determined the following resource   FLAVOUR: \"$res_flavour\""
    hyper_flavour="$(call_hook get_flavour "$hyper" 2>/dev/null)"
    echo "Determined the following hypervisor FLAVOUR: \"$hyper_flavour\""
    res_bz_id="$(call_hook get_bz_id "$res" 2>/dev/null)"
    echo "Determined the following resource   BZ_ID: \"$res_bz_id\""
    hyper_bz_id="$(call_hook get_bz_id "$hyper" 2>/dev/null)"
    echo "Determined the following hypervisor BZ_ID: \"$hyper_bz_id\""
    res_hvt_id="$(call_hook get_hvt_id "$res" 2>/dev/null)"
    echo "Determined the following resource   HVT_ID: \"$res_hvt_id\""
    hyper_hvt_id="$(call_hook get_hvt_id "$hyper" 2>/dev/null)"
    echo "Determined the following hypervisor HVT_ID: \"$hyper_hvt_id\""
    res_hwclass_id="$(call_hook get_hwclass_id "$res" 2>/dev/null)"
    echo "Determined the following resource   HWCLASS_ID: \"$res_hwclass_id\""
    hyper_hwclass_id="$(call_hook get_hwclass_id "$hyper" 2>/dev/null)"
    echo "Determined the following hypervisor HWCLASS_ID: \"$hyper_hwclass_id\""
}

## auto_handover
# Load-balancing accross locations.
# Works only together with the new syntax "cluster123".
# Depending on the number of syncs currently running, this
# will internally add --pre-hand and --post_hand options
# dynamically at runtime. This will spread much of the sync
# traffic to per-datacenter local behaviour.
# Notice: this may produce more total customer downtime when
# running a high parallelism degree.
# Thus it tries to reduce unnecessary handovers to other locations.
auto_handover="${auto_handover:-1}"

## preferred_location
# When set, override any other pre-handover to this location.
# Useful for maintenance of a whole datacenter.
preferred_location="${preferred_location:-}"

check_cluster=""

function cm3_rewrite_args
{
    declare -g -a argv
    echo "Old arguments: ${argv[@]}"
    local res=""
    local arg
    local index=0
    declare -a new_argv=()
    declare -a push_argv=()
    for arg in "${argv[@]}"; do
	if [[ "$arg" =~ ^infong ]]; then
	    res="$arg"
	    new_argv[$(( index++ ))]="$arg"
	elif [[ "$arg" =~ ^cluster ]] && [[ "$res" != "" ]]; then
	    check_cluster="$arg"
	    local location="$(cm3_get_location "$res")"
	    echo "Container '$res' is at '$location'"
	    if [[ "$preferred_location" != "" ]]; then
		echo "Preferred location is '$preferred_location'"
		local check
		for check in $(_get_members "$check_cluster" 2>/dev/null); do
		    local other_location="$(cm3_get_location "$check")"
		    echo "Cluster '$check_cluster' member '$check' is at '$other_location'"
		    if [[ "$other_location" = "$preferred_location" ]] ||\
			[[ "$other_location" =~ ^($preferred_location)$ ]]; then
			echo "Host '$check' is at '$preferred_location'"
			pre_hand="$check"
		    fi
		done
	    fi
	    if [[ "$pre_hand" != "" ]]; then
		local other_location="$(cm3_get_location "$pre_hand")"
		echo "Pre-handover '$pre_hand' location is at '$other_location'"
		if [[ "$other_location" != "" ]]; then
		    location="$other_location"
		fi
	    fi
	    if [[ "$location" = "" ]]; then
		local hyper="$(cm3_get_hyper "$res")"
		location="$(cm3_get_location "$hyper")"
		echo "Hypervisor '$hyper' is at '$location'"
	    fi
	    if [[ "$location" = "" ]]; then
		local store="$(cm3_get_store "$res")"
		location="$(cm3_get_location "$store")"
		echo "Storage '$store' is at '$location'"
	    fi
	    if [[ "$location" = "" ]]; then
		fail "Cannot determine location of '$arg'" "$illegal_status"
	    fi
	    local members="$(echo $(_get_members "$arg") )"
	    echo "Cluster '$arg' has members '$members'"
	    if [[ "$members" =~ istore ]]; then
		members="$(echo $(_get_members "$arg" | grep istore) )"
		echo "Cluster '$arg' has istore members '$members'"
	    fi
	    if [[ "$members" = "" ]]; then
		fail "Cluster members of '$arg' cannot be determined" "$illegal_status"
	    fi
	    local host
	    local best=""
	    local best_syncs=999
	    local best_loc=""
	    local best_pre=""
	    if (( auto_handover )); then
		echo "AUTO_HANDOVER: determine the host with lowest number of running syncs..."
		lock_hosts 1 "$members" ALL
		for host in $members; do
		    host="${host%%.*}"
		    local host_loc="$(cm3_get_location "$host")"
		    echo "Host '$host' is at '$host_loc'"
		    local syncs=0
		    compute_nr_syncs "$host" ""
		    if [[ "$syncs" != "" ]] &&
			( (( syncs < best_syncs )) ||
			    ( (( syncs == best_syncs )) &&
				[[ "$host_loc" = "$location" ]] ) ); then
			echo "Better is '$host' at '$host_loc'"
			best_syncs="$syncs"
			best="$host"
			best_loc="$host_loc"
		    fi
		done
		echo "BEST host is '$best' running '$best_syncs' syncs at '$best_loc'."
		if [[ "$best" != "" ]] && [[ "$best_loc" != "$location" ]]; then
		    local pre_hyper="$(cm3_get_hyper "$res")"
		    echo "Resource '$res' is currently on hypervisor '$pre_hyper'"
		    local pre_cluster="$(_get_cluster_name "$pre_hyper")"
		    echo "Host '$pre_hyper' is on cluster '$pre_cluster'"
		    if [[ "$pre_cluster" = "" ]]; then
			local pre_store="$(cm3_get_store "$res")"
			echo "Resource '$res' is currently on storage '$pre_store'"
			local pre_cluster="$(_get_cluster_name "$pre_store")"
			echo "Host '$pre_store' is on cluster '$pre_cluster'"
		    fi
		    local pre_members="$(echo $(_get_members "$pre_cluster") )"
		    echo "Cluster '$pre_cluster' has storages '$pre_members'"
		    for host in $pre_members; do
			local host_loc="$(cm3_get_location "$host")"
			echo "Host '$host' is at '$host_loc', best is '$best_loc'"
			if [[ "$host_loc" = "$best_loc" ]]; then
			    echo "Better is '$host'"
			    best_pre="$host"
			fi
		    done
		    echo "BEST pre-handover host is '$best_pre'"
		    if [[ "$best_pre" != "" ]]; then
			new_argv[$(( index++ ))]="--pre-hand=$best_pre"
		    fi
		fi
	    fi
	    for host in $members; do
		host="${host%%.*}"
		local host_loc="$(cm3_get_location "$host")"
		echo "Host '$host' is at '$host_loc'"
		if [[ "$best_pre" != "" ]]; then
		    if [[ "$host_loc" = "$best_loc" ]]; then
			new_argv[$(( index++ ))]="$host"
		    else
			push_argv[$(( index++ ))]="$host"
		    fi
		    if [[ "$host_loc" = "$location" ]]; then
			push_argv[$(( index++ ))]="--post_hand=$host"
		    fi
		elif [[ "$host_loc" = "$location" ]]; then
		    new_argv[$(( index++ ))]="$host"
		else
		    push_argv[$(( index++ ))]="$host"
		fi
	    done
	    for host in "${push_argv[@]}"; do
		new_argv[$(( index++ ))]="$host"
	    done
	    lock_hosts
	else
	    new_argv[$(( index++ ))]="$arg"
	fi
    done
    echo "New arguments: ${new_argv[@]}"
    argv=("${new_argv[@]}")
}

function cm3_invalidate_caches
{
    declare -g -A ssh_hyper=()
}


register_module "cm3"
register_command "clustertool"
