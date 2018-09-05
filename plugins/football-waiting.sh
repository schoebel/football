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

## enable_*_waiting
#
# When this is enabled, and when Football had been started by screener,
# then football will delay the start of several operations until a sysadmin
# does one of the following manually:
#
#  a) ./screener.sh continue $session
#  b) ./screener.sh resume $session
#  c) ./screener.sh attach $session and press the RETURN key
#  d) doing nothing, and $wait_timeout has exceeded
#
# CONVENTION: football resource names are used as screener session ids.
# This ensures that only 1 operation can be started for the same resource,
# and it simplifies the handling for junior sysadmins.
#
enable_startup_waiting="${enable_startup_waiting:-0}"
enable_handover_waiting="${enable_handover_waiting:-0}"
enable_migrate_waiting="${enable_migrate_waiting:-0}"
enable_shrink_waiting="${enable_shrink_waiting:-0}"

## enable_cleanup_delayed and wait_before_cleanup
# By setting this, you can delay the cleanup operations for some time.
# This way, you are keeping the old LV contents as a kind of "backup"
# for some limited time.
#
# HINT1: dont set wait_before_cleanup to very large values, because it can
#   seriously slow down Football.
#
# HINT2: the waiting time starts when the last MARS replica was created.
#   Only when the syncing times are _smaller_ than this value,
#   an _additional_ delay will be produced.
enable_cleanup_delayed="${enable_cleanup_delayed:-0}"
wait_before_cleanup="${wait_before_cleanup:-180}" # Minutes

## reduce_wait_msg
# Instead of reporting the waiting status once per minute,
# decrease the frequency of resporting.
# Warning: dont increase this too much. Do not exceed
# session_timeout/2 from screener. Because of the Nyquist criterion,
# stay on the safe side by setting session_timeout at least to _twice_
# the time than here.
reduce_wait_msg="${reduce_wait_msg:-60}" # Minutes

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

function waiting_start_wait
{
    local resource="$1"
    local mode="${2:-waiting}"
    local msg="${3:-$FUNCNAME}"

    if (( !use_screener )); then
	return 0
    fi
    if [[ "$logdir" = "" ]]; then
	echo "Cannot wait: \$logdir is undefined"
	return
    fi

    local i
    for i in {1..5}; do
	echo "-----------------------------------------" >> /dev/stderr
    done

    local flag_file="$logdir/running/$resource.$mode"
    echo "SCREENER_${mode}_START $(date +%s) $(date) flagfile $flag_file $msg"
    echo "$msg" > "$flag_file"
    echo "0" > "$flag_file.count"
    ($script_dir/screener.sh cron)
    return 0
}

function waiting_poll_wait
{
    local resource="$1"
    local mode="${2:-waiting}"
    local abort="${3:-0}"
    local reset_freq="${4:-0}"

    if (( !use_screener )); then
	echo 0
	return 0
    fi
    if [[ "$logdir" = "" ]]; then
	echo 0
	return 0
    fi

    local flag_file="$logdir/running/$resource.$mode"
    if (( abort )); then
	echo "SCREENER_${mode}_ABORT $(date +%s) $(date) remove flagfile '$flag_file' $(< $flag_file)" >> /dev/stderr
	rm -f "$flag_file"
    fi
    if [[ -e "$flag_file" ]]; then
	local freq_wait="$(< "$flag_file.count")"
	if (( freq_wait >= reduce_wait_msg || reset_freq )); then
	    echo "0" > "$flag_file.count"
	    freq_wait=0
	fi
	if (( !freq_wait )); then
	    echo "SCREENER_${mode}_WAIT $(date +%s) $(date) for removal of flagfile '$flag_file' $(< $flag_file)" >> /dev/stderr
	fi
	echo "$(( freq_wait + 1 ))" > "$flag_file.count"
	echo 1
	return
    fi
    local i
    for i in {1..5}; do
	echo "-----------------------------------------" >> /dev/stderr
    done
    echo "SCREENER_${mode}_RESUME $(date +%s) $(date) flagfile $flag_file is gone" >> /dev/stderr
    echo "0" > "$flag_file.count"
    $script_dir/screener.sh cron 1>&2
    echo 0
    return
}

register_module "waiting"
