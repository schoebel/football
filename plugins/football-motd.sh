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

# plugin for motd messages when Football is running
#
# This script must be sourced from the main script.

# Guard against multiple sourcing
[[ "${files[motd]}" != "" ]] && return 0

## enable_motd
# whether to use the motd plugin.
enable_motd="${enable_motd:-0}"

## update_motd_cmd
# Distro-specific command for generating motd from several sources.
# Only tested for Debian Jessie at the moment.
update_motd_cmd="${update_motd_cmd:-update-motd}"

## download_motd_script and motd_script_dir
# When no script has been installed into /etc/update-motd.d/
# you can do it dynamically here, bypassing any "official" deployment
# methods. Use this only for testing!
# An example script (which should be deployed via your ordinary methods)
# can be found under $script_dir/update-motd.d/67-football-running
download_motd_script="${download_motd_script:-}"
motd_script_dir="${motd_script_dir:-/etc/update-motd.d}"

## motd_file
# This will contain the reported motd message.
# It is created by this plugin.
motd_file="${motd_file:-/var/motd/football.txt}"

## motd_color_on and motd_color_off
# ANSI escape sequences for coloring the generated motd message.
motd_color_on="${motd_color_on:-\\033[31m}"
motd_color_off="${motd_color_off:-\\033[0m}"

##########################################################

function motd_describe_plugin
{
    cat <<EOF

PLUGIN football-motd

  Generic plugin for motd. Communicate that Football is running
  at login via motd.

EOF
   show_vars "${files[motd]}"
}

##########################################################

function motd_football_start
{
    (( enable_motd )) || return 0
    local txt="$(echo "$@")"
    declare -g motd_host_list="$(get_full_list "$res $primary $secondary_list $target_primary $target_secondary" 1)"

    echo "MOTD: /etc/motd will be set at $motd_host_list"
    local host
    for host in $motd_host_list; do
	if ! ping -c 1 "$host"; then
	    echo "Skipping host $host"
	    continue
	fi
	if [[ "$download_motd_script" != "" ]]; then
	    # Hack, don't use this regularly
	    #rsync -av $download_motd_script root@$host:$motd_script_dir/
	    local script_target="$motd_script_dir/$(basename $download_motd_script)"
	    remote "$host" "cat > $script_target; chmod +x $script_target" \
		< $download_motd_script
	fi
	{
	    echo ""
	    echo -e "${motd_color_on}FOOTBALL $(date) $txt${motd_color_off}"
	    echo ""
	} | remote "$host" "rm -f $motd_file $motd_file.; mkdir -p $(dirname $motd_file); cat - > $motd_file.$res; $update_motd_cmd || echo IGNORE" 1
    done
    return 0
}

function motd_football_finished
{
    local status="$1"
    shift
    local txt="$(echo "$@")"

    (( enable_motd )) || return 0
    local host
    for host in $motd_host_list; do
	if ! ping -c 1 "$host"; then
	    echo "Skipping host $host"
	    continue
	fi
	remote "$host" "rm -f $motd_file.$res; $update_motd_cmd || echo IGNORE" 1
    done
    return 0
}

register_module "motd"
