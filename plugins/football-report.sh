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

# PLUGIN for communication of migration etc

# Guard agains multiple sourcing
[[ "${files[report]}" != "" ]] && return

## report_cmd_{start,warning,failed,finished}
# External command which is called at start / failure / finish
# of Football.
# The following variables can be used (e.g. as parameters) when
# escaped with a backslash:
#  \$res              = name of the resource (LV, container, etc)
#  \$primary          = the current (old)
#  \$secondary_list   = list of current (old) secondaries
#  \$target_primary   = the target primary name
#  \$target_secondary = list of target secondaries
#  \$operation        = the operation name
#  \$target_percent   = the value used for shrinking
#  \$txt              = some informative text from Football
#  Further variables are possible by looking at the sourcecode, or by
#  defining your own variables or functions externally or via plugins.
# Empty = don't do anything
report_cmd_start="${report_cmd_start:-}"
report_cmd_warning="${report_cmd_warning:-$script_dir/screener.sh notify \"\$res\" warning \"\$txt\"}"
report_cmd_failed="${report_cmd_failed:-}"
report_cmd_finished="${report_cmd_finished:-}"

##########################################################

function report_describe_plugin
{
    cat <<EOF

PLUGIN football-report

  Generic plugin for communication of reports.

EOF
   show_vars "${files[report]}"
}

##########################################################

function _report
{
    local cmd="$1"
    local txt="$2"

    [[ "$cmd" = "" ]] && return
    (
	eval "$cmd"
    )
}

function report_football_start
{
    local txt="$(echo "$@")"
    _report "$report_cmd_start" "$txt"
}

function report_football_warning
{
    local txt="$(echo "$@")"
    _report "$report_cmd_warning" "$txt"
}

function report_football_failed
{
    local txt="$(echo "$@")"
    _report "$report_cmd_failed" "$txt"
}

report_finished_called=0

function report_football_finished
{
    local status="$1"
    shift
    local txt="$(echo "$@")"

    if (( !report_finished_called++ )); then
	_report "$report_cmd_finished" "$txt"
    fi
}

register_module "report"
