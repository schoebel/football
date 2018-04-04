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
    try="$(remote "$host" "nc \$(iscsiadm -m session -o show | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+') 101 2>/dev/null | cut -d. -f1" 1)"
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
	remote "$host" "lvrename $lvremove_opt $path.old" 1
    else
	remote "$host" "lvremove $lvremove_opt $path" 1
    fi
    local rc=$?
    if (( fail_ignore )); then
	return 0
    fi
    return $rc
}

function cm3_resource_locked
{
    local res="$1"

    # heuristics: tar processes indicate a running movespace or backup restore
    local something="$(remote "$res" "ps ax" | grep "/bin/tar ")"
    if [[ "$something" != "" ]]; then
	echo "RESOURCE_LOCK $(date +%s) $(date) resource $res is locked" >> /dev/stderr
	echo 1
    else
	echo 0
    fi
}

function cm3_resource_stop
{
    local host="$1"
    local res="$2"

    declare -g  downtime_begin
    [[ "$downtime_begin" = "" ]] && downtime_begin="$(date +%s)"
    echo "DOWNTIME BEGIN $(date)"
    ssh_hyper[$host]=""
    # stop the whole stack
    remote "$host" "cm3 --stop $res || cm3 --stop $res || { mountpoint /vol/$res && umount /vol/$res; } || false"
}

function cm3_resource_stop_vm
{
    local hyper="$1"
    local res="$2"

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
    remote "$host" "marsadm primary $res"
    remote "$host" "cm3 --stop $res; cm3 --start $res || { cm3 --stop $res; cm3 --start $res; } || false"
    echo "DOWNTIME END   $(date)"
    declare -g  downtime_begin
    declare -g  downtime_end="$(date +%s)"
    echo "DOWNTIME END $(date) ($(( downtime_end - downtime_begin )) s)"
    remote "$host" "if [[ -x /usr/sbin/nodeagent ]]; then /usr/sbin/nodeagent status; fi"
}

function cm3_resource_start_vm
{
    local hyper="$1"
    local res="$2"

    # start only the vm
    # precondition is that mounts etc are already present
    remote "$hyper" "nodeagent vmstart $res"
    declare -g  downtime_begin
    declare -g  downtime_end="$(date +%s)"
    echo "DOWNTIME END $(date) ($(( downtime_end - downtime_begin )) s)"
    remote "$hyper" "if [[ -x /usr/sbin/nodeagent ]]; then /usr/sbin/nodeagent status; fi"
}

function cm3_resource_check
{
    local res="$1"
    local timeout="${2:-10}"

    local host="$res"
    echo "Checking whether $host is running...."
    while ! ping $ping_opts $host; do
	if (( timeout-- <= 0 )); then
	    echo "HOST $host DOES NOT PING!"
	    return
	fi
	sleep 3
    done
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
	    remote "$host" "systemctl disable ui-firewalling.service || echo IGNORE"
	    remote "$host" "service ui-firewalling stop || /etc/init.d/firewalling stop"
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
	local hyper_port="$(cm3_ssh_port "$hyper" 2>/dev/null)"
	if cm3_check_port "$hyper" "${hyper_port##* }" 1>&2; then
	    local found="$(ssh $hyper_port $ssh_opt "root@$hyper" "lxc-ls -1" | grep "^$host$")"
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
do_split_cluster="${do_split_cluster:-1}"

function cm3_merge_cluster
{
    local source="$1"
    local target="$2"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return

    if (( ip_magic )); then
	# This MAGIC may be needed when mutual icpu / istore
	# ssh connects via hostnames are disallowed
	# by some network firewall rules.
	# Workaround by going down to the replication IPs.
	local source_ip="$(remote "$source" "marsadm lowlevel-ls-host-ips" | grep "$source" | awk '{ print $2; }')"
	echo "Peer '$source' has IP '$source_ip'"
	source="$source_ip"
    fi
    remote "$target" "marsadm merge-cluster --ssh-port=24 $source"
}

function cm3_split_cluster
{
    local host_list="$1"

    if (( do_split_cluster )); then
	local ok=0
	local host
	local old_host
	local retry
	for (( retry=0; retry < 3; retry++ )); do
	    for host in $host_list; do
		sleep 5
		if remote "$host" "marsadm split-cluster --ssh-port=24" 1; then
		    ok=1
		    break
		fi
		old_host="$host"
		remote "$host" "marsadm wait-cluster" 1
	    done
	    (( ok )) && break
	    # try to fix asymmetric clusters by mutual re-merging
	    for host in $host_list; do
		sleep 5
		if remote "$host" "marsadm merge-cluster --ssh-port=24 $old_host" 1; then
		    ok=1
		    break
		fi
		old_host="$host"
		remote "$host" "marsadm wait-cluster" 1
	    done
	done
	if (( !ok )); then
	    fail "Please run 'marsadm split-cluster --ssh-port=24' by hand"
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

    remote "$target" "marsadm join-resource --force --ssh-port=24 $res $dev"
}

###########################################

# General checks

# This is deliberately not documented.
needed_marsadm="${needed_marsadm:-2.1 1.1}"
needed_mars="${needed_mars:-0.1stable49 0.1abeta0 mars0.1abeta0}"
max_cluster_size="${max_cluster_size:-4}"
max_syncs="${max_syncs:-2}"

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
    fail "$type actual version '$actual' does not match one of '$needed_list'"
}

function cm3_check_host
{
    local host_list="$1"

    local host
    for host in $host_list; do
	local marsadm_version="$(remote "$host" "marsadm --version" | grep -o 'Version: [0-9.]*' | awk '{ print $2; }')"
	echo "Installed marsadm version at $host: '$marsadm_version'"
	check_needed "marsadm" "[0-9]\." "$marsadm_version" "$needed_marsadm"

	local mars_version="$(remote "$host" "cat /sys/module/mars/version" | awk '{ print $1; }')"
	if [[ "$mars_version" = "" ]]; then
	    fail "MARS kernel module is not loaded at $host"
	fi
	check_needed "mars kernel module" "[a-z]*[0-9.]*[a-z]*" "$mars_version" "$needed_mars"
    done

    echo "Checking that max_cluster_size=$max_cluster_size will not be exceeded at $host_list"
    local new_cluster_size="$(
        for host in $host_list; do
            remote "$host" "marsadm lowlevel-ls-host-ips" 2>/dev/null
        done | sort -u | wc -l)"
    if (( new_cluster_size < 2 )); then
	fail "Implausible new cluster size $new_cluster_size"
    fi
    echo "New cluster size: $new_cluster_size"
    if (( new_cluster_size > max_cluster_size )); then
	fail "Cluster size limit $max_cluster_size will be exceeded, aborting."
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
    if (( max_syncs >= 0 && actual_syncs > max_syncs )); then
	fail "There are more than $max_syncs syncs running."
    fi

    # Workaround missing performance tuning which has not been rolled out for months now
    for host in $host_list; do
	local cmd="for i in \$(find /sys/devices/pci* -name nr_requests); do echo \"\$(cat \$i) \$i\"; echo 920 > \$i; done"
	remote "$host" "$cmd"
    done
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
clustertool_user="${clustertool_user:-$(shopt -u nullglob; ls *.password | head -1 | cut -d. -f1)}" || fail "cannot find a password file *.password for clustermw"

## clustertool_passwd
# Here you can supply the encrpted password.
# By default, a file $clustertool_user.password is used
# containing the encrypted password.
clustertool_passwd="${clustertool_passwd:-$(cat $clustertool_user.password)}"

echo "Using clustermw username: '$clustertool_user'"

function clustertool
{
    local op="${1:-GET}"
    local path="${2:-/clusters}"
    local content="$3"

    local cmd="curl -s -u \"$clustertool_user:$clustertool_passwd\" -X \"$op\" \"$clustertool_host$path\""
    [[ "$content" != "" ]] && cmd+=" -d '${content//\'/\'}'"
    echo "$cmd" | sed -u 's/\(curl .*\)-u *[^ ]*/\1/' >> /dev/stderr
    eval "$cmd" || fail "failed REST command '$cmd'"
}

function _get_cluster_name
{
    local host="$1"

    local url="/vms/$host.schlund.de"
    [[ "$host" =~ icpu ]] && url="/nodes/$host.schlund.de"
    [[ "$host" =~ istore ]] && url="/storagehosts/$host.schlund.de"
    clustertool GET "$url" |\
	grep -o "cluster[0-9]\+" |\
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

function cm3_get_flavour
{
    local host="$1"

    clustertool GET "/nodes/$host.schlund.de" |\
	json_pp |\
	grep flavour |\
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

## backup_dir
# Directory for keeping JSON backups of clustermw.
backup_dir="${backup_dir:-.}"

function _check_migrate
{
    local source="$1"
    local target="$2"
    local res="$3"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return
    [[ "$res" = "" ]] && return

    local source_cluster="$(_get_cluster_name "$source")" || fail "cannot get source_cluster"
    local target_cluster="$(_get_cluster_name "$target")" || fail "cannot get target_cluster"

    echo "source_cluster='$source_cluster'"
    echo "target_cluster='$target_cluster'"

    [[ "$source_cluster" = "" ]] && fail "cm3 source cluster is undefined"
    [[ "$target_cluster" = "" ]] && fail "cm3 target cluster is undefined"

    if [[ "$source_cluster" != "$target_cluster" ]]; then
	if (( check_segments )); then
	    # At the moment, cross-segment migrations won't work.
	    # TBD.
	    local source_segment="$(_get_segment "$source_cluster")" || fail "cannot get source_segment"
	    local target_segment="$(_get_segment "$target_cluster")" || fail "cannot get target_segment"
	    echo "source_segment='$source_segment'"
	    echo "target_segment='$target_segment'"
	    if (( check_segments > 1 )); then
		[[ "$source_segment" = "" ]] && fail "cannot determine source segment"
		[[ "$target_segment" = "" ]] && fail "cannot determine target segment"
		[[ "$source_segment" != "$target_segment" ]] && fail "source_segment '$source_segment' != target_segment '$target_segment'"
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

    if (remote "$host" "cm3 -us") | grep -q " $res "; then
	echo "1"
    else
	echo "0"
    fi
}

function cm3_migrate_cm3_config
{
    local source="$1"
    local target="$2"
    local res="$3"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return
    [[ "$res" = "" ]] && return

    local source_cluster="$(_get_cluster_name "$source")" || fail "cannot get source_cluster"
    local target_cluster="$(_get_cluster_name "$target")" || fail "cannot get target_cluster"
    if (( always_migrate )) || [[ "$source_cluster" != "$target_cluster" ]]; then
	echo "Moving config from cluster '$source_cluster' to cluster '$target_cluster'"

	local backup=""
	if [[ "$backup_dir" != "" ]]; then
	    local backup="$backup_dir/json-backup.$start_stamp"
	    mkdir -p $backup
	fi

	local status_url="/vms/$res.schlund.de"
	clustertool GET "$status_url" |\
	    log "$backup" "$res.old.raw.json" |\
	    json_pp |\
	    log "$backup" "$res.old.pp.json"

	if ! [[ -s "$backup/$res.old.raw.json" ]]; then
	    fail "cluster config for vm '$res' is empty"
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
    local secondary_list="$(remote "$primary" "marsadm view-resource-members $res" | { grep -v "^$primary$" || true; })" || fail "cannot determine secondary_list"
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
    local secondary_list="$(remote "$primary" "marsadm view-resource-members $res" | { grep -v "^$primary$" || true; })" || fail "cannot determine secondary_list"
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
	    local max_rounds=10
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

    local old_tids="$(remote "$store" "cat /proc/net/iet/volume /proc/net/iet/session" | grep -o 'tid:[0-9]\+' | cut -d: -f2 | sort -u)"
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
    for hyper in $(remote "$store" "grep -A1 'name:$iqn' < /proc/net/iet/session | grep 'initiator:' | grep -o 'icpu[0-9]\+'"); do
	remote "$hyper" "iscsiadm -m node -T $iqn -u || echo IGNORE iSCSI initiator logout"
    done
    # safeguarding: retrieve any matching tid
    local tid
    for tid in $(remote "$store" "grep 'name:$iqn' < /proc/net/iet/volume | cut -d' ' -f1 | cut -d: -f2"); do
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

    local vg_name="$(get_vg "$store")" || fail "cannot determine VG for host '$store'"
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
    remote "$hyper" "ls /dev/sd?" > $tmp_list
    remote "$hyper" "iscsiadm -m node -p $iscsi_ip -T $iqn -l"
    while true; do
	sleep 3
	local new_dev="$(remote "$hyper" "ls /dev/sd?" | diff -u $tmp_list - | grep '^+/' | cut -c2-)"
	[[ -n "$new_dev" ]] && break
    done
    rm -f $tmp_list
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

function cm3_invalidate_caches
{
    declare -g -A ssh_hyper=()
}

register_module "cm3"
