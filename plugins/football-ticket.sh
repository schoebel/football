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

   You will need to hook in some external scripts which are
   then creating / updating the tickets.

   Comment texts may be provided with following conventions:

     comment.\$ticket_state.txt
     comment.\$ticket_phase.\$ticket_state.txt

   Directories where comments may reside:

     football_creds=$football_creds
     football_confs=$football_confs
     football_includes=$football_includes

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
# Retrieval should be unique by resource names.
# You may use any defined bash varibale by escaping them like
# \$res .
# Example: ticket_get_cmd="my-ticket-getter-script.pl \"\$res\""
ticket_get_cmd="${ticket_get_cmd:-}"

## ticket_create_cmd
# Optional: when set, this script can be used for creating new tickets.
# It will be called when \$ticket_get_cmd does not retrieve anything.
# Example: ticket_create_cmd="my-ticket-create-script.pl \"\$res\" \"\$target_primary\""
# Afterwards, the new ticket needs to be retrievable via \$ticket_get_cmd.
ticket_create_cmd="${ticket_create_cmd:-}"

## ticket_update_cmd
# This can be used for calling an external command which updates
# the ticket(s) given by the $ticket parameter.
# Example: ticket_update_cmd="my-script.pl \"$ticket\" \"$res\" \"$ticket_phase\" \"$ticket_state\""
ticket_update_cmd="${ticket_update_cmd:-}"

## ticket_require_comment
# Only update a ticket when a comment file exists in one of the
# directories \$football_creds \$football_confs \$football_includes
ticket_require_comment="${ticket_require_comment:-1}"

## ticket_for_migrate
# Optional 1&1-specific: separate ticket for migrate.
# Useful when migrate+shink need to post into separate tickets.
ticket_for_migrate="${ticket_for_migrate:-}"

## ticket_for_shrink
# Optional 1&1-specific: separate ticket for migrate.
# Useful when migrate+shink need to post into separate tickets.
ticket_for_shrink="${ticket_for_shrink:-}"

function ticket_call_fn
{
    local cmd="$1"

    [[ "$cmd" = "" ]] && return

    cmd="$(eval "echo \"$cmd\"")"
    echo "Calling ticket command: '$cmd'" >> /dev/stderr
    (eval "$cmd")
    echo "Ticket command rc=$?" >> /dev/stderr
}

function _get_ticket_id
{
    local operation="$1"
    local res="$2"
    # output in $ticket

    echo "Trying to get ticket ID for operation '$operation' resource '$res'"
    ticket="$(ticket_call_fn "$ticket_get_cmd")"
    echo "Got ticket ID '$ticket'"
    if [[ "$parse_ticket" != "" ]] && echo "$ticket" | grep -o -e "$parse_ticket"; then
	ticket="$(echo "$ticket" | grep -o -e "$parse_ticket" | head -1)"
    elif [[ "$ticket" =~ ERROR ]]; then
	ticket=""
    fi
    if [[ "$ticket" = "" ]] &&\
	[[ "$ticket_create_cmd" != "" ]]; then
	echo "Trying to create a new ticket for resource '$res'"
	ticket_call_fn "$ticket_create_cmd"
	ticket="$(ticket_call_fn "$ticket_get_cmd")"
	echo "Got ticket ID '$ticket'"
	if [[ "$ticket" =~ ERROR ]]; then
	    ticket=""
	fi
    fi
}

## ticket_prefer_cached
# Workaround a bug in ticket ID retrieval:
# Trust my own cached values more than trust the "inconsistent read".
ticket_prefer_cached="${ticket_prefer_cached:-1}"

function ticket_pre_init
{
    if [[ "$res" = "" ]]; then
	return
    fi
    local old_ticket="$ticket"
    local old_operation="$operation"
    local operation
    for operation in ${old_operation//+/_} shrink migrate; do
	if [[ "$(eval echo \${ticket_for_$operation})" != "" ]]; then
	    echo "Ticket for operation '$operation' is '$(eval echo \${ticket_for_$operation})'"
	    continue
	fi
	ticket="$old_ticket"
	echo "Initial ticket='$ticket' for operation '$operation'"
	mkdir -p $football_logdir/tickets
	local ticket_file="$football_logdir/tickets/ticket.$operation.$res.txt"
	if [[ "$ticket" != "" ]] && \
	    [[ -s "$ticket_file" ]] && \
	    (( ticket_prefer_cached )); then
	    ticket="$(< $ticket_file)"
	    echo "Preferring ticket '$ticket' from file '$ticket_file'"
	fi
	if [[ "$ticket" = "" ]] &&\
	    [[ "$ticket_update_cmd" != "" ]] &&\
	    [[ "$ticket_get_cmd" != "" ]]; then
	    echo "Retrieving ticket for operation '$operation'"
	    _get_ticket_id "$operation" "$res"
	fi
	if [[ "$ticket" = "" ]]; then
	    ticket="$(< $ticket_file)"
	    echo "Got ticket '$ticket' from file '$ticket_file'"
	else
	    echo "Storing ticket '$ticket' into '$ticket_file'"
	    echo "$ticket" > "$ticket_file"
	fi
	eval "ticket_for_$operation=\"$ticket\""
	echo "Ticket for operation '$operation' is now '$(eval echo \${ticket_for_$operation})'"
    done
}

last_ticket_phase=""
fail_ticket_phase=""
fail_ticket_state=""

function ticket_update_ticket
{
    local ticket_phase="$1"
    local ticket_state="$2"

    if [[ "$ticket_phase" = "" ]]; then
	echo "Using last_ticket_phase '$last_ticket_phase'"
	ticket_phase="$last_ticket_phase"
    fi
    if [[ "$ticket_phase" = "" ]]; then
	echo "Using phase '$phase'"
	ticket_phase="$phase"
    fi
    echo "ticket_phase='$ticket_phase' ticket_state='$ticket_state'"
    if [[ "$ticket_phase" != "" ]]; then
	last_ticket_phase="$ticket_phase"
    fi

    [[ "$ticket_update_cmd" = "" ]] && return

    local comment_glob="comment.$ticket_state.txt"
    local comment_file="$(get_cred_file "$comment_glob")"
    if [[ "$comment_file" = "" ]]; then
	echo "There is no comment file '$comment_glob' in $football_creds $football_confs $football_includes"
	comment_glob="comment.$ticket_phase.$ticket_state.txt"
	comment_file="$(get_cred_file "$comment_glob")"
    fi
    if [[ "$comment_file" = "" ]] && (( !ticket_require_comment )); then
	echo "There is no comment file '$comment_glob' in $football_creds $football_confs $football_includes"
	return
    fi
    echo "Using comment file '$comment_file'"
    local comment=""
    if [[ "$comment_file" != "" ]]; then
	comment="$(< $comment_file)"
	echo "Original comment is '$comment'"
	comment="$(eval "echo \"$comment\"")"
	echo "Evaluated comment is '$comment'"
    fi
    if [[ "$comment" = "" ]]; then
	echo "Comment is empty."
	return
    fi

    if [[ "$ticket_state" =~ running ]]; then
	fail_ticket_phase="$ticket_phase"
	fail_ticket_state="${ticket_state//running/failed}"
    else
	fail_ticket_phase=""
	fail_ticket_state=""
    fi
    if [[ "$ticket_phase" =~ migrate ]] && [[ "$ticket_for_migrate" != "" ]]; then
	echo "Using ticket_for_migrate"
	ticket="$ticket_for_migrate" ticket_call_fn "$ticket_update_cmd"
    elif [[ "$ticket_phase" =~ shrink ]] && [[ "$ticket_for_shrink" != "" ]]; then
	echo "Using ticket_for_shrink"
	ticket="$ticket_for_shrink" ticket_call_fn "$ticket_update_cmd"
    else
	echo "Using default ticket '$ticket'"
	ticket_call_fn "$ticket_update_cmd"
    fi
    return 0
}

function ticket_football_failed
{
    local status="$1"

    echo "Ticket for exit status=$status"
    if [[ "$fail_ticket_phase" != "" ]]; then
	local ticket_state="$fail_ticket_state"
	if (( status == critical_status )); then
	    ticket_state="${fail_ticket_state//failed/critical}"
	elif (( status == serious_status )); then
	    ticket_state="${fail_ticket_state//failed/serious}"
	elif (( status == interrupted_status )); then
	    ticket_state="${fail_ticket_state//failed/interrupted}"
	elif (( status == illegal_status )); then
	    ticket_state="${fail_ticket_state//failed/illegal}"
	fi
	echo "Reporting failure into ticket: '$fail_ticket_phase' '$ticket_state'"
	ticket_update_ticket "$fail_ticket_phase" "$ticket_state"
	fail_ticket_phase=""
	fail_ticket_state=""
    fi
    return 0
}

###########################################

register_module "ticket"