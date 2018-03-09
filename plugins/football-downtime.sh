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

# PLUGIN for creating / communicating a customer downtime

# Guard agains multiple sourcing
[[ "${files[downtime]}" != "" ]] && return

## downtime_cmd_{set,unset}
# External command for setting / unsetting (or communicating) a downtime
# Empty = don't do anything
downtime_cmd_set="${downtime_cmd_set:-}"
downtime_cmd_unset="${downtime_cmd_unset:-}"

##########################################################

function downtime_describe_plugin
{
    cat <<EOF

PLUGIN football-downtime

  Generic plugin for communication of customer downtime.

EOF
   show_vars "${files[downtime]}"
}

##########################################################

critical_section=0

function downtime_want_downtime
{
    local resource="$1"
    local down="${2:-0}"

    echo "WANT_DOWNTIME $resource $down"
    # ... insert your code here
}

function downtime_report_downtime
{
    local resource="$1"
    local down="${2:-0}"

    echo "REPORT_DOWNTIME $resource $down"
    if (( down )); then
	declare -g critical_section=1
	echo "SCREENER_CRITICAL=1 $(date +%s) $(date)" >> /dev/stderr
	[[ "$downtime_cmd_set" = "" ]] && return
	$downtime_cmd_set "$resource" || echo IGNORE
    else
	declare -g critical_section=0
	echo "SCREENER_CRITICAL=0 $(date +%s) $(date)" >> /dev/stderr
	[[ "$downtime_cmd_unset" = "" ]] && return
	$downtime_cmd_unset "$resource"
    fi
}

register_module "downtime"
