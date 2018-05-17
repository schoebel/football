#!/bin/bash
#
# This file is part of MARS project: http://schoebel.github.io/mars/
#
# Copyright (C) 2018 Thomas Schoebel-Theuer
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

#############################################

# Container Football

# Basic MARS plugin
# Assumption: the MARS resources are controlled via marsadm,
# e.g. indirectly via systemd.

# Guard against multiple sourcing
[[ "${files[basic]}" != "" ]] && return

#############################################

function basic_describe_plugin
{
    cat <<EOF

PLUGIN football-basic

   Generic driver for systemd-controlled MARS pools.
   The current version supports only a flat model:
   (1) There is a single "big cluster" at metadata level.
       All cluster members are joined via merge-cluster.
       All occurring names need to be globally unique.
   (2) The network uses BGP or other means, thus any hypervisor
       can (potentially) start any VM at any time.
   (3) iSCSI or remote devices are not supported for now
       (LocalSharding model). This may be extended in a future
       release.
   This plugin is exclusive-or with cm3.

Plugin specific actions:

   $0 basic_add_host <hostname>
      Manually add another host to the hostname cache.

EOF
   show_vars "${files[collector]}"
   show_vars "${files[basic]}"
}

#############################################

## enable_basic
# This plugin is exclusive-or with cm3.
enable_basic="${enable_basic:-$(if [[ "$0" =~ football ]]; then echo 1; else echo 0; fi)}"

(( enable_basic )) || return 0

#############################################

## ssh_port
# Set this for separating sysadmin access from customer access
ssh_port="${ssh_port:-}"

function basic_ssh_port
{
    local host="$1"
    local for_marsadm="${2:-0}"

    if [[ "$ssh_port" != "" ]]; then
	if (( for_marsadm )); then
	    echo "--ssh-port=$ssh_port"
	else
	    echo "-p $ssh_port"
	fi
    fi
}

#############################################

## basic_mnt_dir
# Names the mountpoint directory at hypervisors.
# This must co-incide with the systemd mountpoints.
basic_mnt_dir="${basic_mnt_dir:-/mnt}"

function basic_get_mountpoint
{
    local res="$1"
    echo "$basic_mnt_dir/$res"
}

function basic_get_hyper
{
    local res="$1"
    basic_get_store "$res"
}

function basic_get_store
{
    local host="$1"

    local cand_hosts="$(grep ":$res\$" < "$res2hyper_cache" | cut -d: -f1 | sort -u)"
    local host
    for host in $cand_hosts; do
	remote "$host" "marsadm view-get-primary $res"
    done |\
	sort -u |\
	tail -1
}

function basic_get_vg
{
    local host="$1"

    # Heuristics: take the biggest VG
    remote "$host" "vgs --units=k" |\
	grep -v "VSize" |\
	sed 's/\.[0-9]*k//g' |\
	awk '{ if ($6 > big) { big = $6; name = $1; } } END{ print name; }'
	
}

function basic_resource_locked
{
    local res="$1"
    # NYI
    echo "0"
}

function basic_resource_stop
{
    local host="$1"
    local res="$2"

    local cmd="systemctl stop \$(marsadm get-systemd-unit $res | sed 's/^.* //')"
    remote "$host" "$cmd"
}

function basic_resource_stop_vm
{
    local hyper="$1"
    local res="$2"

    local unit="$(remote "$hyper" "marsadm get-systemd-unit $res" | sed 's/^.* //')"
    if [[ "$unit" = "" ]]; then
	fail "systemd unit is not set on host '$hyper'"
    fi
    if [[ "$unit" =~ \.mount$ ]]; then
	echo "Skipping umount of '$unit' on '$hyper'"
	return
    fi
    local cmd="systemctl stop \"$unit\""
    remote "$hyper" "$cmd"
}

function basic_resource_stop_rest
{
    local hyper="$1"
    local primary="$2"
    local res="$3"
    basic_resource_stop "$primary" "$res"

    # For saftety (should be done automatically)
    local retry
    for (( retry=1; retry < 3; retry++ )); do
	sleep 3
	cmd="systemctl status \$(marsadm get-systemd-unit $res | sed 's/^.* //' || echo IGNORE)"
	if ! remote "$host" "$cmd" | grep active; then
	    break
	fi
	cmd="systemctl stop \$(marsadm get-systemd-unit $res | sed 's/^.* //')"
	remote "$host" "$cmd"
    done
}

function basic_resource_start
{
    local host="$1"
    local res="$2"

    local cmd="marsadm primary $res"
    remote "$host" "$cmd"

    # For saftety (should be done automatically)
    local retry
    for (( retry=1; retry < 3; retry++ )); do
	sleep 3
	cmd="systemctl status \$(marsadm get-systemd-unit $res | sed 's/ .*$//' || echo IGNORE)"
	if remote "$host" "$cmd" | grep active; then
	    break
	fi
	cmd="systemctl start \$(marsadm get-systemd-unit $res | sed 's/ .*$//')"
	remote "$host" "$cmd"
    done
}

function basic_resource_start_vm
{
    local hyper="$1"
    local res="$2"
    basic_resource_start "$hyper" "$res"
}

function basic_is_startable
{
    local host="$1"
    local res="$2"

    echo "1"
}

function basic_resource_check
{
    local res="$1"
    local timeout="${2:-10}"
    echo "NYI"
}

function basic_prepare_hosts
{
    local host_list="$1"
    echo "NYI"
}

function basic_finish_hosts
{
    local host_list="$1"
    echo "NYI"
}

#############################################

function basic_save_resource_state
{
    local host="$1"
    local res="$2"

    local units="$(remote "$host" "marsadm get-systemd-unit $res" 1)"
    if [[ "$units" != "" ]]; then
	local status_file="$football_logdir/resource.$res.status"
	echo "Saving units $units to $status_file"
	echo "$units" > $status_file
    fi
}

function basic_restore_resource_state
{
    local host="$1"
    local res="$2"

    local status_file="$football_logdir/resource.$res.status"
    if [[ -s "$status_file" ]]; then
	local units="$(< "$status_file")"
	if [[ "$units" = "" ]]; then
	    warn "Status file $status_file contains no units - Problems are expected"
	    return
	fi
	units="${units//\\/\\\\}"
	echo "Restoring units $unit from $status_file"
	remote "$host" "marsadm set-systemd-unit $res $units || marsadm set-systemd-unit $res $units --force"
    fi
}

#############################################

function basic_pre_init
{
    # Uses the collector plugin
    hostname_init
    resources_init
}

function basic_add_host
{
    local new_host="$1"

    if ! ping -c1 $new_host; then
	fail "host '$new_host' is not pingable."
    fi
    echo "$new_host" >> "$hostname_cache"
    basic_pre_init
}

register_module "basic"
register_command "basic_add_host"
