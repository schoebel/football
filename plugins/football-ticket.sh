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

# Generic plugin for creating / updating Jira tickets
# via calls of external scripts.
#
# This script must be sourced from the main script.

# Guard agains multiple sourcing
[[ "${files[ticket]}" != "" ]] && return

function ticket_describe_plugin
{
    cat <<EOF

PLUGIN football-ticket

   Generic plugin for creating and updating tickets,
   e.g. Jira tickets.

EOF
   show_vars "${files[ticket]}"
}

register_description "ticket"

###########################################

## enable_ticket
enable_ticket="${enable_ticket:-$(if [[ "$0" =~ tetris ]]; then echo 1; else echo 0; fi)}"

(( enable_ticket )) || return 0

###########################################

## ticket
# OPTIONAL: the meaning is installation specific.
# This can be used for identifying JIRA tickets.
# Can be set on the command line like "./tetris.sh $args --ticket=TECCM-4711
ticket="${ticket:-}"

## ticket_get_cmd
# Optional: when set, this script can be used for retrieving ticket IDs
# in place of commandline option --ticket=
ticket_get_cmd="${ticket_get_cmd:-}"

## ticket_update_cmd
# This can be used for calling an external command which updates
# the ticket(s) given by the $ticket parameter.
ticket_update_cmd="${ticket_update_cmd:-}"

function ticket_pre_init
{
    if [[ "$ticket" = "" ]] &&\
	[[ "$ticket_update_cmd" != "" ]] &&\
	[[ "$ticket_get_cmd" != "" ]]; then
	echo "Trying to get ticket ID for resource '$res'"
	ticket="$($ticket_get_cmd $res)"
	echo "Got ticket ID '$ticket'"
    fi
}

ticket_compensation=""

function ticket_update_ticket
{
    local ticket_phase="$1"
    local ticket_state="$2"

    [[ "$ticket" = "" ]] && return
    [[ "$ticket_update_cmd" = "" ]] && return

    local cmd="$ticket_update_cmd \"$ticket\" \"$res\" \"$ticket_phase\" \"$ticket_state\""
    echo "ticket: $cmd"
    if [[ "$ticket_state" =~ running ]]; then
	ticket_compensation="${cmd//running/failed}"
    else
	ticket_compensation=""
    fi
    (eval "$cmd")
    return 0
}

function ticket_football_failed
{
    if [[ "$ticket_compensation" != "" ]]; then
	local cmd="$ticket_compensation"
	ticket_compensation=""
	echo "ticket: $cmd"
	(eval "$cmd")
    fi
    return 0
}

###########################################

register_module "ticket"