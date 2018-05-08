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

# Infrastructure for mass data collection / caching

function mass_collect_data
{
    local hostname_list="${1:-$(< "$hostname_cache")}"
    local remote_cmd="$2"
    local local_cmd="${3:-}"
    local convolution="${4:-sort -u}"
    local tmpfile="${5:-/tmp/FIFO.$$}"
    local split="${6:-3}"

    local host
    local nr="$(echo $hostname_list | wc -w)"
    if (( nr <= split )); then
	for host in $hostname_list; do
	    if [[ "$local_cmd" != "" ]]; then
		remote "$host" "$remote_cmd" 1 |\
		    eval "$local_cmd"
	    else
		remote "$host" "$remote_cmd" 1
	    fi
	done |\
	    eval "$convolution"
	return
    fi
    local -a sub_list=()
    local i=0
    for host in $hostname_list; do
	local sub_nr=$(( i % split ))
	(( i++ ))
	sub_list[$sub_nr]="${sub_list[$sub_nr]} $host"
    done
    local tmpfile_list=""
    for (( i = 0; i < split; i++ )); do
	if [[ "$tmpfile" =~ FIFO ]]; then
	    mkfifo "$tmpfile.$i"
	fi
	tmpfile_list+=" $tmpfile.$i"
	mass_collect_data "${sub_list[$i]}" "$remote_cmd" "$local_cmd" "$convolution" "$tmpfile.$i" "$split" > "$tmpfile.$i" &
    done
    sleep 1
    if ! [[ "$tmpfile" =~ FIFO ]]; then
	wait
    fi
    cat $tmpfile_list |\
	eval "$convolution"
    rm -f $tmpfile_list
}

#############################################

## pool_cache_dir
# Directory for caching the pool status.
pool_cache_dir="${pool_cache_dir:-$script_dir/pool-cache}"

## initial_hostname_file
# This file must contain a list of storage and/or hypervisor hostnames
# where a /mars directory must exist.
# These hosts are then scanned for further cluster members,
# and the transitive closure of all host names is computed.
initial_hostname_file="${initial_hostname_file:-./hostnames.input}"

## hostname_cache
# This file contains the transitive closure of all host names.
hostname_cache="${hostname_cache:-$pool_cache_dir/hostnames.cache}"

function hostname_init
{
    local tmp_file="/tmp/hostname_cache.tmp.$$"

    # Initialize cache from initial file when present
    if [[ -s "$initial_hostname_file" ]]; then
	echo "Processing initial hostname file $initial_hostname_file"
	mkdir -p $pool_cache_dir
	{ cat "$initial_hostname_file" "$hostname_cache" 2>/dev/null ||\
	    true
	} | sort -u > "$tmp_file" &&\
	    mv "$tmp_file" "$hostname_cache"
    fi

    if ! [[ -s "$hostname_cache" ]]; then
	rm -f "$tmp_file"
	fail "Initial hostname cache is empty: please provide a file $initial_hostname_file"
    fi

    local retry
    for (( retry = 0; retry < 10; retry++ )); do
	mass_collect_data "$(< "$hostname_cache")" "marsadm view-cluster-members" |\
	    sort -u > "$tmp_file"
	if cmp "$tmp_file" "$hostname_cache" >/dev/null; then
	    break
	fi
	echo "Re-computing transitive closure on $(wc -l < "$hostname_cache") -> $(wc -l < "$tmp_file") hosts"
	mv "$tmp_file" "$hostname_cache"
	sleep 3
    done
    rm -f "$tmp_file"
    echo "Number of known host names: $(wc -l < "$hostname_cache")"
}

#############################################

## resources_cache
# This file contains the transitive closure of all resource names.
resources_cache="${resources_cache:-$pool_cache_dir/resources.cache}"

## res2hyper_cache
# This file contains the association between resources and hypervisors.
res2hyper_cache="${res2hyper_cache:-$pool_cache_dir/res2hyper.assoc}"

function resources_init
{
    local tmp_file="$resources.tmp.$$"
    mass_collect_data "" "marsadm view-all-resources" > "$tmp_file"
    if [[ -s "$tmp_file" ]]; then
	echo "Total number of distinct resources: $(wc -l < "$resources_cache") -> $(wc -l < "$tmp_file")"
	mv "$tmp_file" "$resources_cache"
    else
	echo "No resources found."
	rm -f "$tmp_file"
    fi
    mass_collect_data "" "marsadm view-my-resources" "sed \"s/^/\$host:/\"" > "$tmp_file"
    if [[ -s "$tmp_file" ]]; then
	echo "Total number of replicas: $(wc -l < "$res2hyper_cache") -> $(wc -l < "$tmp_file")"
	mv "$tmp_file" "$res2hyper_cache"
    fi
    rm -f "$tmp_file"
}

#############################################

register_module "collector"
