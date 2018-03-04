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

############################################################

# TST March 2018 started in my spare time on my private computer

# PLUGIN: football waiting for "screener.sh continue"

# Guard agains multiple sourcing
[[ "${files[waiting]}" != "" ]] && return

## enable_critical_waiting
#
# When this is enabled, and when Football had been started by screener,
# then football will delay the start of several operations until a sysadmin
# might lead to customer downtime) until a sysadmin does a manual
# "screener.sh continue" operation.
#
# CONVENTION: football resource names are used as screener session ids.
# This ensures that only 1 operation can be started for the same resource,
# and it simplifies the handling for junior sysadmins.
#
enable_critical_waiting="${enable_critical_waiting:-0}"

function waiting_describe_plugin
{
    cat <<EOF

PLUGIN football-waiting

  Generic plugig, interfacing with screener: when this is used
  by your script and enabled, then you will be able to wait for
  "screener.sh continue" operations at certain points in your
  script.

EOF
   show_vars "${files[waiting]}"
}

function waiting_start_critical
{
    local resource="$1"
    local msg="${2:-$FUNCNAME}"

    if (( !enable_critical_waiting || !use_screener )); then
	return 0
    fi

    local flag_file="$logdir/running/$resource.waiting"
    echo "SCREENER_WAITING_START $(date +%s) $(date) flagfile $flag_file $msg"
    echo "$msg" > "$flag_file"
    $script_dir/screener.sh cron
}

function waiting_poll_critical
{
    local resource="$1"

    if (( !enable_critical_waiting || !use_screener )); then
	return 0
    fi

    local flag_file="$logdir/running/$resource.waiting"
    if [[ -e "$flag_file" ]]; then
	echo "WAITING $(date) for removal of flagfile '$flag_file' $(< $flag_file)" >> /dev/stderr
	echo 1
	return
    fi
    echo "SCREENER_WAITING_RESUME $(date +%s) $(date) flagfile $flag_file is gone" >> /dev/stderr
    echo 0
    return
}

register_module "waiting"
