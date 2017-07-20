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

# 1&1 specific plugin / hooks for working with Jessie icpu conventions and cm3
#
# This script must be sourced from the main script.

commands_installed "curl json_pp"

function hook_get_mountpoint
{
    local res="$1"
    echo "/vol/$res"
}

function hook_get_hyper
{
    local res="$1"

    remote "$res" "source /lib/ui-config-framework/bash-includes; __config_getConfigVar HWNODE_NAME; echo \$HWNODE_NAME | cut -d. -f1"
}

function hook_get_store
{
    local host="$1"
    
    try="$(remote "$host" "source /lib/ui-config-framework/bash-includes; __config_getConfigVar CLUSTER_STORAGEHOST; echo \$CLUSTER_STORAGEHOST | cut -d. -f1")"
    if [[ "$try" != "" ]]; then
	echo "$try"
	return
    fi
    # fallback to indirect retrieval
    local hyper="$(hook_get_hyper "$host")"
    if [[ "$hyper" != "" ]] && [[ "$hyper" != "$host" ]]; then
	hook_get_store "$hyper"
    fi
}

function hook_get_vg
{
    local host="$1"
    
    remote "$host" "vgs | awk '{ print \$1; }' | grep 'vginfong\|vg[0-9]\+[ab]'"
}

function hook_resource_stop
{
    local host="$1"
    local res="$2"

    # stop the whole stack
    remote "$host" "cm3 --stop $res || cm3 --stop $res || { mountpoint /vol/$res && umount /vol/$res; } || false"
}

function hook_resource_stop_vm
{
    local hyper="$1"
    local res="$2"

    # stop only the vm, keep intermediate mounts etc
    remote "$hyper" "nodeagent vmstop $res"
}

function hook_resource_stop_rest
{
    local hyper="$1"
    local primary="$2"
    local res="$3"

    # stop the rest of the stack
    remote "$hyper" "nodeagent stop $res"
    local mnt="$(hook_get_mountpoint "$res")"
    remote "$hyper" "mountpoint $mnt && { umount -f $mnt ; exit \$?; } || true"
    hook_resource_stop "$primary" "$res"
}

function hook_resource_start
{
    local host="$1"
    local res="$2"

    remote "$host" "marsadm wait-cluster"
    remote "$host" "service clustermanager restart"
    remote "$host" "marsadm primary $res"
    remote "$host" "cm3 --stop $res; cm3 --start $res || { cm3 --stop $res; cm3 --start $res; } || false"
}

###########################################

# Workarounds for firewalling (transitional => TBD)

workaround_firewall="${workaround_firewall:-1}"

function hook_prepare_hosts
{
    local host_list="$1"

    if (( workaround_firewall )); then
	local host
	for host in $host_list; do
	    remote "$host" "service ui-firewalling stop || /etc/init.d/firewalling stop"
	done
    fi
}

function hook_finish_hosts
{
    local host_list="$1"

    if (( workaround_firewall )); then
	local host
	for host in $host_list; do
	    remote "$host" "service ui-firewalling restart || /etc/init.d/firewalling restart"
	done
    fi
}

###########################################

# Workarounds for ssh between different clusters

ip_magic="${ip_magic:-1}"

function hook_merge_cluster
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

function hook_join_resource
{
    local source="$1"
    local target="$2"
    local res="$3"
    local dev="$4"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return
    [[ "$res" = "" ]] && return

    remote "$target" "marsadm join-resource --ssh-port=24 $res $dev"
}

###########################################

# Mini infrastucture for access to clustermw

clustertool_host="${clustertool_host:-http://clustermw:3042}"
clustertool_user="${clustertool_user:-$(shopt -u nullglob; ls *.password | head -1 | cut -d. -f1)}" || fail "cannot find a password file *.password for clustermw"
clustertool_passwd="${clustertool_passwd:-$(cat $clustertool_user.password)}"

echo "Using clustermw username: '$clustertool_user'"

function clustertool
{
    local op="${1:-GET}"
    local path="${2:-/clusters}"
    local content="$3"

    local cmd="curl -s -u \"$clustertool_user:$clustertool_passwd\" -X \"$op\" \"$clustertool_host$path\""
    [[ "$content" != "" ]] && cmd+=" -d '${content//\'/\'}'"
    echo "$cmd" >> /dev/stderr
    eval "$cmd" || fail "failed REST command '$cmd'"
}

###########################################

# Attention: this is provisionary.
# Later versions should not need this anymore.

use_rest="${use_rest:-1}"
sasoap="${sasoap:-sasoap-eu1}"

function _get_cluster_name
{
    local host="$1"

    if (( use_rest )); then
	local url="/vms/$host.schlund.de"
	[[ "$host" =~ icpu ]] && url="/nodes/$host.schlund.de"
	[[ "$host" =~ istore ]] && url="/storagehosts/$host.schlund.de"
	clustertool GET "$url"
    else
	remote "$sasoap" " ui-clustertool property_show --hostname $host.schlund.de"
    fi |\
	grep -o "cluster[0-9]\+" |\
	sort -u
}

function _get_segment
{
    local cluster="$1"

    if (( use_rest )); then
	local url="/clusters/$cluster"
	clustertool GET "$url" |\
	    json_pp |\
	    grep '"segment"' |\
	    cut -d: -f2 |\
	    sed 's/[ ",]//g'
    else
	remote "$sasoap" " ui-clustertool cluster_show --clustername $cluster" |\
	    grep NETWORK_SEGMENT |\
	    awk '{ print $2; }'
    fi
}

###########################################

# Migration operation: move cm3 config from old cluster to a new cluster

do_migrate="${do_migrate:-1}" # must be enabled; disable for dry-run testing
always_migrate="${always_migrate:-0}" # only enable for testing
check_segments="${check_segments:-0}" # currently disabled for testing, might be needed for real moves
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

    if [[ "$source_cluster" != "$target_cluster" ]]; then
	if (( check_segments )); then
	    # At the moment, cross-segment migrations won't work.
	    # TBD.
	    local source_segment="$(_get_segment "$source_cluster")" || fail "cannot get source_segment"
	    local target_segment="$(_get_segment "$target_cluster")" || fail "cannot get target_segment"
	    echo "source_segment='$source_segment'"
	    echo "target_segment='$target_segment'"
	    [[ "$source_segment" = "" ]] && fail "cannot determine source segment"
	    [[ "$target_segment" = "" ]] && fail "cannot determine target segment"
	    [[ "$source_segment" != "$target_segment" ]] && fail "source_segment '$source_segment' != target_segment '$target_segment'"
	fi
    fi

}

function _migrate_cm3_config
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

	if (( use_rest )); then
	    local backup=""
	    if [[ "$backup_dir" != "" ]]; then
		local backup="$backup_dir/json-backup.$start_stamp"
		mkdir -p $backup
	    fi

	    local status_url="/vms/$res.schlund.de"
	    clustertool GET "$status_url" 2>&1 |\
		log "$backup" "$res.old.raw.json" |\
		json_pp 2>&1 |\
		log "$backup" "$res.old.pp.json"

	    local old_url="/clusters/$source_cluster/vms/$res.schlund.de"
	    local new_url="/clusters/$target_cluster/vms/$res.schlund.de"
	    echo clustertool DELETE "$old_url"
	    (( do_migrate )) && clustertool DELETE "$old_url"
	    echo clustertool PUT    "$new_url"
	    (( do_migrate )) && clustertool PUT    "$new_url"

	    clustertool GET "$status_url" 2>&1 |\
		log "$backup" "$res.new.raw.json" |\
		json_pp 2>&1 |\
		log "$backup" "$res.new.pp.json"

	    diff -ui $backup/$res.pp.old.json $backup/$res.pp.new.json
	    clustertool PUT "/clusters/$source_cluster/properties/CLUSTERCONF_SERIAL"
	    clustertool PUT "/clusters/$target_cluster/properties/CLUSTERCONF_SERIAL"
	    sleep 3
	    remote "$source" "cm3 --update --force"
	    remote "$target" "cm3 --update --force"
	    sleep 3
	    remote "$source" "service clustermanager restart"
	    remote "$target" "service clustermanager restart"
	    sleep 3
	else
	    remote "$sasoap" "ui-clustertool export_infongconf --infongname $res.schlund.de"
	    echo "NYI... hopefully this variant is never needed - otherwise remove this stub"
	fi
    else
	echo "Source and target clusters are equal: '$source_cluster'"
	echo "Nothing to do."
    fi
}

function hook_check_migrate
{
    local source="$1"
    local target="$2"
    local res="$3"

    _check_migrate "$source" "$target" "$res"
}

function hook_resource_migrate
{
    local source="$1"
    local target="$2"
    local res="$3"

    _migrate_cm3_config "$source" "$target" "$res"
}

function hook_secondary_migrate
{
    local secondary_list="$1"

    local secondary
    for secondary in $secondary_list; do
	remote "$secondary" "cm3 --update --force"
	remote "$secondary" "service clustermanager restart"
    done
}

function hook_determine_old_replicas
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

function hook_determine_new_replicas
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

# Hooks for shrinking

iqn_base="${iqn_base:-iqn.2000-01.info.test:test}"
iet_type="${iet_type:-blockio}"
iscsi_eth="${iscsi_eth:-eth1}"
iscsi_tid="${iscsi_tid:-4711}"
declare -g -A tids

function hook_disconnect
{
    local store="$1"
    local hyper="$2"
    local res="$3"
    local tid_offset="${4:-0}"

    declare -g iscsi_tid
    declare -g -A tids

    local iqn="$iqn_base.$res.tmp"
    local tid="${tids["$iqn"]}"
    [[ "$tid" = "" ]] && tid=$(( iscsi_tid + tid_offset ))

    remote "$hyper" "iscsiadm -m node -T $iqn -u || echo IGNORE"
    remote "$store" "ietadm --op delete --tid=$tid || echo IGNORE"
}

function hook_connect
{
    local store="$1"
    local hyper="$2"
    local res="$3"
    local tid_offset="${4:-0}"

    declare -g iscsi_tid
    declare -g -A tids

    # for safety, kill any old session
    hook_disconnect "$store" "$hyper" "$res" "$tid_offset"

    local vg_name="$(get_vg "$store")" || fail "cannot determine VG for host '$store'"
    local dev="/dev/$vg_name/$res"
    local iqn="$iqn_base.$res.tmp"
    local iscsi_ip="$(remote "$store" "ifconfig $iscsi_eth" | grep "inet addr:" | cut -d: -f2 | awk '{print $1;}')"
    echo "using iscsi IP '$iscsi_ip'"

    # saftey check
    remote "$hyper" "ping -c1 $iscsi_ip"

    # step 1: setup stone-aged IET on storage node
    local tid=$(( iscsi_tid + tid_offset ))
    remote "$store" "ietadm --op new --tid=$tid --params=Name=$iqn"
    remote "$store" "ietadm --op new --tid=$tid --lun=0 --params=Path=$dev"
    tids["$iqn"]="$tid"
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
    declare -g iscsi_tid=$(( tid + 1 ))
    echo "New iscsi tid: $iscsi_tid"
    echo "NEW_DEV:$new_dev"
}

###########################################

# Hooks for extending of XFS

function hook_extend_iscsi
{
    local hyper="$1"

    remote "$hyper" "iscsiadm -m session -R"
}
