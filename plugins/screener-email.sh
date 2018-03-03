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

# PLUGIN for automatic sending of emails, SMS via gateways, etc

# Guard agains multiple sourcing
[[ "${files[email]}" != "" ]] && return

## email_*
# List of email addresses.
# Empty = don't send emails.
email_critical="${email_critical:-}"
email_serious="${email_serious:-}"
email_failed="${email_failed:-}"
email_warning="${email_warning:-}"
email_waiting="${email_waiting:-}"
email_done="${email_done:-}"

## sms_*
# List of email addresses of SMS gateways.
# These may be distinct from email_*.
# Empty = don't send sms.
sms_critical="${sms_critical:-}"
sms_serious="${sms_serious:-}"
sms_failed="${sms_failed:-}"
sms_warning="${sms_warning:-}"
sms_waiting="${sms_waiting:-}"
sms_done="${sms_done:-}"

## email_cmd
# Command for email sending.
# Please include your gateways etc here.
email_cmd="${email_cmd:-mailx -S smtp=mx.nowhere.org:587 -S smpt-auth-user=test}"

## email_logfiles
# Whether to include logfiles in the body.
# Not used for sms_*.
email_logfiles="${email_logfiles:-1}"

##########################################################

function email_describe_plugin
{
    cat <<EOF

PLUGIN screener-email

  Generic plugin for sending emails (or SMS via gateways)
  upon status changes, such as script failures.

EOF
   show_vars "${files[email]}"
}

##########################################################

function _send_email
{
    local id="$1"
    local op="$2"
    local to="$3"
    local mode="${4:-email}"

    [[ "$to" = "" ]] && return

    local real_op="$op"
    [[ "$op" =~ waiting|delayed|warning ]] && real_op="running"
    local logfile="$screener_logdir/$real_op/$id.log"
    local title="${5:-$(grep SCREENER_TITLE= < $logfile | tail -1 | cut -d= -f2-)}"
    local subject="SCREENER $op $title ($id)"
    echo "Sending $mode $op '$title' $id => $to"
    {
	local dir
	local txtfile
	for dir in $football_includes; do
	    for txtfile in $dir/screener-$mode.txt $dir/screener-$mode-$op.txt; do
		(( verbose )) && echo "Including $txtfile" >> /dev/stderr
		[[ -s $txtfile ]] && cat $txtfile
	    done
	done
	if (( email_logfiles )) && [[ -s "$logfile" ]] && [[ "$mode" != sms ]]; then
	    cat < $logfile
	fi
    } | $email_cmd -s "$subject" $to
    echo "Send $to status=$?"
}

function email_notify
{
    local id="$1"
    local status="$2"
    local title="$3"

    local sms_list="$(eval echo \${sms_$status})"
    _send_email "$id" "$status" "$sms_list" sms "$title"
    local email_list="$(eval echo \${email_$status})"
    _send_email "$id" "$status" "$email_list" email "$title"
}

register_module "email"