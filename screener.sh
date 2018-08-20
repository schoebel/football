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

set -o pipefail
shopt -s nullglob
export LC_ALL=C

# common *.conf and *.sh include infrastructure
script_dir="$(dirname "$(which "$0")")"

## screener_includes
# List of directories where screener-*.conf files can be found.
screener_includes="${screener_includes:-/usr/lib/mars/plugins /etc/mars/plugins $script_dir/plugins $HOME/.mars/plugins ./plugins}"

## screener_confs
# Another list of directories where screener-*.conf files can be found.
# These are sourced in a second pass after $screener_includes.
# Thus you can change this during the first pass.
screener_confs="${screener_confs:-/usr/lib/mars/confs /etc/mars/confs $script_dir/confs $HOME/.mars/confs ./confs}"

declare -g -A files=()
declare -g file
declare -g module_list=""
declare -g description_list=""
declare -g plugin_command_list=""

function register_module
{
    local module="$1"

    if [[ "$module" != "" ]]; then
	files[$module]="$file"
	module_list+=" $module"
    fi
}

function register_command
{
    local command_list="$1"

    if [[ "$command_list" != "" ]]; then
	plugin_command_list+=" $command_list"
    fi
}

function register_description
{
    local description="$1"

    if [[ "$description" != "" ]]; then
	files[$description]="$file"
	description_list+=" $description"
    fi
}

# Sourcing of config files and modules in multiple passes

function source_glob
{
    local dirs="$1"
    local pattern="$2"
    local txt="$3"
    local abort="${4:-1}"

    local dir
    for dir in $dirs; do
	local file
	for file in $(eval "echo $dir/$pattern"); do
	    if ! [[ -r "$file" ]]; then
		echo "$txt: file '$file' is not readable" >> /dev/stderr
		continue
	    fi
	    if (( verbose )); then
		echo "$txt: sourcing $file" >> /dev/stderr
	    fi
	    if ! source "$file"; then
		echo "Cannot source '$file'" >> /dev/stderr
		if (( abort )); then
		    exit -1
		fi
	    fi
	done
    done
}

source_glob "$screener_confs"    "screener-*.preconf"  "Pass1a"
source_glob "$screener_includes" "screener-*.preconf"  "Pass1b"
source_glob "$screener_confs"    "screener-*.conf"     "Pass2a"
source_glob "$screener_includes" "screener-*.conf"     "Pass2b"
source_glob "$screener_includes" "infra-*.sh"          "Pass3"
source_glob "$screener_includes" "screener-*.sh"       "Pass4"
source_glob "$screener_confs"    "screener-*.postconf" "Pass5a"
source_glob "$screener_includes" "screener-*.postconf" "Pass5b"
source_glob "$screener_confs"    "screener-*.reconf"   "Pass6a"
source_glob "$screener_includes" "screener-*.reconf"   "Pass6b"

# OPTIONS, also overridable via --option=$value

## title
# Used as a title for startup of screen sessions, and later for
# display at list-*
title="${title:-}"

## auto_attach
# Upon start or upon continue/wakuep/up, attach to the
# (newly created or existing) session.
auto_attach="${auto_attach:-0}"

## auto_attach_grace
# Before attaching, wait this time in seconds.
# The user may abort within this sleep time by
# pressing Ctrl-C.
auto_attach_grace="${auto_attach_grace:-10}"

## force_attach
# Use "screen -x" instead of "screen -r" allowing
# shared sessions between different users / end terminals.
force_attach="${force_attach:-0}"

## drop_shell
# When a <cmd> fails, the screen session will not terminated immediately.
# Instead, an interactive bash is started, so can later attach and
# rectify any probllems.
# WARNING! only activate this if you regulary check for failed sessions
# and then manually attach to them. Don't use this when running hundreds
# or thousand in parallel.
drop_shell="${drop_shell:-0}"

## session_timeout
# Detect hanging sessions when they don't produce any output anymore
# for a longer time. Hanging sessions are then marked as failed or critical.
session_timeout="${session_timeout:-$(( 3600 * 3 ))}" # seconds

## screener_logdir or logdir
# Where the logfiles and all status information is kept.
export screener_logdir="${screener_logdir:-${logdir:-$HOME/screener-logs}}"

## screener_command_log
# This logfile will accumulate all relevant $0 command invocations,
# including timestamps and ssh agent identities.
# To switch off, use /dev/null here.
screener_command_log="${screener_command_log:-$screener_logdir/commands.log}"

## screener_cron_log
# Since "$0 cron" works silently, you won't notice any errors.
# This logfiles gives you a chance for checking any problems.
screener_cron_log="${screener_cron_log:-$screener_logdir/cron.log}"

## screener_log_purge_period
# $0 cron or $0 purge will automatically remove all old logfiles
# from $screener_logdir/*/ when this period is exceeded.
screener_log_purge_period="${screener_log_purge_period:-30}" # Days

## dry_run
# Dont actually start screen sessions when set.
dry_run="${dry_run:-0}"

## verbose
# increase speakiness.
verbose=${verbose:-0}

## debug
# Some additional debug messages.
debug="${debug:-0}"

## sleep
# Workaround races by keeping sessions open for a few seconds.
# This is useful for debugging of immediate script failures.
# You have some short time window for attaching.
# HINT: instead, just inspect the logfiles in $screener_logdir/*/*.log
sleep="${sleep:-3}"

## screen_cmd
# Customize the screen command (e.g. add some further options, etc).
screen_cmd="${screen_cmd:-screen}"

## use_screenlog
# Add the -L option. Not really useful when running thousands of
# parallel screen sessions, because the automatically generated filenames
# are crap, and cannot be set in advance.
# Useful for basic debugging of setup problems etc.
use_screenlog="${use_screenlog:-0}"

## waiting_txt and delay_txt and condition_txt
# RTFS Don't use this, unless you know what you are doing.
waiting_txt="${waiting_txt:-SCREENER_waiting_WAIT}"
delayed_txt="${delayed_txt:-SCREENER_delayed_WAIT}"
condition_txt="${condition_txt:-SCREENER_condition_WAIT}"

## critical_status
# This is the "magic" exit code indicating _criticality_
# of a failed command.
critical_status="${critical_status:-199}"

## serious_status
# This is the "magic" exit code indicating _seriosity_
# of a failed command.
serious_status="${serious_status:-198}"

## less_cmd
# Used at $0 less $id
less_cmd="${less_cmd:-less -r}"

## date_format
# Here you can customize the appearance of list-* commands
date_format="${date_format:-%Y-%m-%d %H:%M}"

## csv_delimit
# The delimiter used for CSV file parsing
csv_delim="${csv_delim:-;}"

## csv_cmd_fields
# Regex telling the field name for 'cmd'
csv_cmd_fields="${csv_cmd_fields:-command}"

## csv_id_fields
# Regex telling the field name for 'screen_id'
csv_id_fields="${csv_id_fields:-screen_id|resource}"

## csv_remove
# Regex for global removal of command options
csv_remove="${csv_remove:---screener}"

############################################################

function commands_installed
{
    local cmd_list="$1"

    local cmd
    for cmd in $cmd_list; do
	if ! which $cmd > /dev/null; then
	    fail "shell command '$cmd' is not installed"
	fi
    done
}

screener_commands_needed="${screener_commands_needed:-screen bash dirname basename stat touch sleep grep sed awk sort head tail tee ls cat cut date mkdir rmdir rm mv wc}"

############################################################

# option parsing

function parse_option
{
    local par="$1"

    if [[ "$par" = "--help" ]]; then
	op=help
    elif [[ "$par" =~ "=" ]]; then
	par="${par#--}"
	lhs="$(echo "$par" | cut -d= -f1)"
	rhs="$(echo "$par" | cut -d= -f2-)"
	lhs="${lhs//-/_}"
	echo "OVERRIDE $lhs=$rhs"
	eval "$lhs=$rhs" || exit $?
    else
	par="${par#--}"
	par="${par//-/_}"
	echo "OVERRIDE $par=1"
	eval "$par=1" || exit $?
    fi
}

while [[ "$1" =~ ^-- ]]; do
    par="$1"
    shift
    parse_option "$par"
done

############################################################

# PARAMETERS

op="${op:-$1}"
id="${id:-$2}"

## user_name
# Normally automatically derived from ssh agent or from $LOGNAME.
# Please override this only when really necessary.
export user_name="${user_name:-$(ssh-add -l | grep -o '[^ ]\+@[^ ]\+' | sort -u | tail -1)}"
export user_name="${user_name:-$LOGNAME}"

# Self-documenting command invocation log
if ! [[ "$op" =~ help|cron|list|show|less|status ]]; then
    echo "$(date +%s) $(date "+%F_%T") user_name=$user_name $0 $@" >> "$screener_command_log"
fi

######################################################################

function call_hook
{
    local name="$1"
    shift

    local module
    for module in $module_list generic; do
	local m_name="${module}_$name"
	if [[ "$(type -t $m_name)" =~ function ]]; then
	    (( verbose )) && echo "Running hook: $m_name $@"
	    $m_name "$@"
	fi
    done 1>&2 >> /dev/stderr
}

function show_vars
{
    local script="$1"

    (( !verbose )) && return

    local matches=0
    local line
    while read line; do
	if [[ "$line" =~ ^\#\#\  ]]; then
	    matches=1
	elif [[ "$line" = "" ]]; then
	    (( matches )) && echo ""
	    matches=0
	fi
	if (( matches )); then
	    echo "  $line"
	fi
    done < "$script"
}

function screen_help
{
cat <<EOF
$0: Run _unattended_ processes in screen sessions.
    Useful for MASS automation, running hundreds of unattended
    commands in parallel.
    HINT: for running more than ~500 sessions in parallel, you might need
    some system tuning (e.g. rlimits, kernel patches etc) for creating
    a huge number of file descritor / sockets / etc.
    ADVANTAGE: You may attach to individual screens, kill them, or continue
    some waiting commands.

Synopsis:
  $0 --help [--verbose]
  $0 list-running
  $0 list-waiting
  $0 list-failed
  $0 list-critical
  $0 list-serious
  $0 list-done
  $0 list
  $0 list-screens
  $0 run <file.csv> [<condition_list>]
  $0 start <screen_id> <cmd> <args...>
  $0 [<options>] <operation> <screen_id>

Inquiry operations:

  $0 list-screens
    Equivalent to $screen_cmd -ls

  $0 list-<type>
    Show a list of currently running, waiting (for continuation), failed,
    and done/completed screen sessions.

  $0 list
    First show a list of currently running screens, then
    for each <type> a list of (old) failed / completed / sessions
    (and so on).

  $0 status <screen_id>
    Like list-*, but filter <sceen_id> and dont report timestamps.

  $0 show <screen_id>
    Show the last logfile of <screen_id> at standard output.

  $0 less <screen_id>
    Show the last logfile of <screen_id> using "$less_cmd".

MASS starting of screen sessions:

  $0 run <file.csv> <condition_list>
    Commands are launched in screen sessions via "$0 start" commands,
    unless the same <screen_id> is already running,
    or is in some error state, or is already done (see below).
    The commands are given by a column with CSV header name
    containing "$csv_cmd_fields", or by the first column.
    The <screen_id> needs to be given by a column with CSV header
    name matching "$csv_id_fields".
    The number and type of commands to launch can be reduced via
    any combination of the following filter conditions:

      --max=<number>
        Limit the number of _new_ sessions additionally started this time.

      --<column_name>==<value>
        Only select lines where an arbitrary CSV column (given by its
        CSV header name in C identifier syntax) has the given value.

      --<column_name>!=<value>
        Only select lines where the colum has _not_ the given value.

      --<column_name>=~<bash_regex>
        Only select lines where the bash regular expression matches
        at the given column.

      --max-per=<number>
        Limit the number per _distinct_ value of the column denoted by
        the _next_ filter condition.
        Example: $0 run test.csv --dry-run --max-per=2 --dst_network=~.
        would launch only 2 Football processes per destination network.

    Hint: filter conditions can be easily checked by giving --dry-run.

Start / restart / kill / continue screen sessions:

  $0 start <screen_id> <cmd> <args...>
    Start a new screen session, running arbitrary <cmd> and <args...>
    inside.

  $0 restart <screen_id>
    Works only when the last command for <screen_id> failed.
    This will restart the old <cmd> and its <args...> as before.
    Use only when you want to repeat the same command once again.

  $0 kill <screen_id>
    Terminate the running screen session forcibly.

  $0 continue
  $0 continue <screen_id> [<screen_id_list>]
  $0 continue <number>
    Useful for MASS automation of processes involving critical sections
    such as customer downtime.
    When giving a numerical <number> argument, up to that number
    of sessions are resumed (ordered by age).
    When no further arugment is given, _all_ currently waiting sessions
    are continued.
    When --auto-attach is given, it will sequentially resume the
    sessions to be continued. By default, unless --force_attach is set,
    it uses "screen -r" skipping those sessions which are already
    attached to somebody else.
    This feature works only with prepared scripts which are creating
    an empty flagfile
    $screener_logdir/running/\$screen_id.waiting
    whenever they want to wait for manual intervention (for whatever reason).
    Afterwards, the script must be polling this flagfile for removal.
    This screener operation simply removes the flagfile, such that
    the script will then continue afterwards.
    Example: look into $(dirname "$0")/football.sh
    and search for occurrences of substring "call_hook start_wait".

  $0 wakeup
  $0 wakeup <screen_id> [<screen_id_list>]
  $0 wakeup <number>
    Similar to continue, but refers to delayed commands waiting for
    a timeout. This can be used to individually shorten the timeout
    period.
    Example: Football cleanup operations may be artificially delayed
    before doing "lvremove", to keep some sort of 'backup' for a
    limited time. When your project is under time pressure, these
    delays may be hindering.
    Use this for premature ending of such artificial delays.

  $0 up <...>
    Do both continue and wakeup.

  $0 auto <...>
    Equivalent to $0 --auto-attach up <...>
    Remember that only session without current attachment will be
    attached to.

Attach to a running session:

  $0 attach <screen_id>
    This is equivalent to $screen_cmd -x \$screen_id

  $0 resume <screen_id>
    This is equivalent to $screen_cmd -r \$screen_id

Communication:

  $0 notify <screen_id> <txt>
    May be called from external scripts to send emails etc.

Locking (only when supported by <cmd>):

  $0 lock
  $0 unlock
  $0 lock <screen_id>
  $0 unlock <screen_id>

Cleanup / bookkeeping:

  $0 clear-critical <screen_id>
  $0 clear-serious <screen_id>
  $0 clear-failed  <screen_id>
    Mark the status as "done" and move the logfile away.

  $0 purge [<days>]
    This will remove all old logfiles which are older than
    <days>. By default, the variable \$screener_log_purge_period
    will be used, which is currently set to '$screener_log_purge_period'.

  $0 cron
    You should call this regulary from a user cron job, in order
    to purge old logfiles, or to detect hanging sessions, or to
    automatically send pending emails, etc.

Options:

  --variable
  --variable=\$value
    These must come first, in order to prevent mixup with
    options of <cmd> <args...>.
    Allows overriding of any internal shell variable.
  --help --verbose
    Show all overridable shell variables, also for plugins.

EOF
   show_vars "$0"
   call_hook describe_plugin 2>&1
}

############################################################

function warn
{
    local txt="$1"
    echo "WARNING: $txt" >> /dev/stderr
}

function fail
{
    local txt="${1:-Unknown failure}"
    echo "FAILURE: $txt" >> /dev/stderr
    #exit -1
    kill $BASHPID
}

############################################################

# status handling

status_dir_list="running critical serious failed done"

for i in $status_dir_list; do
    mkdir -p "$screener_logdir/$i"
done

function has_status
{
    local id="$1"
    local list="${status_dir_list}"

    local status
    for status in $list; do
	local check="$screener_logdir/$status/$id.log"
	if [[ -s "$check" ]]; then
	    echo "$status"
	    return 0
	fi
    done
    return 1
}

function change_status
{
    local id="$1"
    local src_state="$2"
    local dst_state="$3"

    if [[ "$src_state" = "$dst_state" ]]; then
	return
    fi

    local src_log="$screener_logdir/$src_state/$id.log"
    local dst_log="$screener_logdir/$dst_state/$id.log"

    if ! [[ -e "$src_log" ]]; then
	return
    fi

    echo "CHANGE $id: $src_state => $dst_state" >> /dev/stderr

    call_hook leave  "$id" "$src_state"
    call_hook notify "$id" "$dst_state"

    if [[ -e "$dst_log" ]]; then
	echo "Appending $src_log to $dst_log" >> /dev/stderr
	if mv "$src_log" "$src_log.tmp"; then
	    cat "$src_log.tmp" >> "$dst_log" ||\
		fail "cannot copy '$src_log.tmp' => '$dst_log'"
	    rm -f "$src_log.tmp"
	fi
    else
	mv "$src_log" "$dst_log"
    fi
    rm -f $screener_logdir/$src_state/$id.wait*
}

function get_status
{
    local id="$1"

    # check for aborts and session_timeouts
    local check="$screener_logdir/running/$id.log"
    if [[ -s $check ]]; then
	local status="$(grep -o "^STATUS=[0-9]\+$" < "$check" | tail -1)"
	if [[ "$status" = "" ]]; then
	    local critical_section="$(grep -o "^SCREENER_CRITICAL=[0-9]" < "$check" | tail -1 | cut -d= -f2-)"
	    # check for terminated screen sessions
	    if ! screen_exists "$id" 2>&1 > /dev/null; then
		warn "SESSION_LOST $id critical=$critical_section"
		echo "" >> "$check"
		echo "SCREENER_SESSION_LOST $(date +%s) $(date)" >> "$check"
		status="-1"
		(( critical_section )) && status="$critical_status"
	    elif (( session_timeout > 0 )); then
		# check for session_timeouts
		local stamp="$(stat --format="%X" "$check")"
		if (( stamp && stamp + session_timeout < $(date +%s) )); then
		    warn "TIMEOUT $id critical=$critical_section"
		    screen_kill "$id" 0
		    local i
		    for (( i = 0; i < 3; i++ )); do
			local session="$(screen_exists "$id")"
			(( !session )) && break
			sleep 1
		    done
		    echo "" >> "$check"
		    echo "SCREENER_TIMEOUT $(date +%s) $(date)" >> "$check"
		    status="-1"
		    (( critical_section )) && status="$critical_status"
		fi
	    fi
	    if [[ "$status" != "" ]]; then
		echo "STATUS=$status" >> "$check"
	    fi
	fi
	if [[ "$status" != "" ]]; then
	    status="${status##*=}"
	    if (( !status )); then
		# Success. Also move any previous failure logs.
		change_status "$id" failed done
		change_status "$id" critical done
		change_status "$id" serious done
		change_status "$id" running done
	    elif (( status == critical_status )); then
		change_status "$id" running critical
	    elif (( status == serious_status )); then
		change_status "$id" running serious
	    else
		change_status "$id" running failed
	    fi
	fi
    fi
    # Check waiting flagfile
    for status in waiting delayed condition; do
	local flagfile="$screener_logdir/running/$id.$status"
	if [[ -e $flagfile ]] ||\
	    ( [[ -s $check ]] && \
	    grep "^SCREENER_${status}_" < $check | tail -1 | grep -q -v RESUME); then
	    # notify only once per waiting state entered
	    if ! [[ -e "$flagfile.hook_called" ]]; then
		rm -f $screener_logdir/running/$id.*.hook_called
		call_hook notify "$id" "$status" "$(< $flagfile)"
		touch "$flagfile.hook_called"
	    fi
	    echo "$status"
	    return
	fi
	rm -f "$flagfile.hook_called"
    done
    for status in $status_dir_list; do
	check="$screener_logdir/$status/$id.log"
	if [[ -s "$check" ]]; then
	    echo "$status"
	    return
	fi
    done
    echo "unknown"
}

function list_screens
{
    $screen_cmd -ls
}

function list_status
{
    local types="${1:-$status_dir_list}"
    local show_stamp="${2:-1}"
    local filter="${3:-}"

    local type
    for type in $types; do
	if (( show_stamp )) && [[ "$types" =~ " " ]]; then
	    echo "List of $type:"
	fi
	local real_type="$type"
	[[ "$type" =~ waiting|delayed|condition ]] && real_type=running
	local name
	for name in $screener_logdir/$real_type/*.log; do
	    local id="${name##*/}"
	    id="${id%.log}"
	    if [[ "$filter" != "" ]] && ! [[ "$id" =~ $filter ]]; then
		continue
	    fi
	    local status="$(get_status "$id")"
	    [[ -e "$name" ]] || continue
	    if [[ "$status" = running ]] && [[ "$type" =~ waiting|delayed|condition ]]; then
		continue
	    fi
	    if [[ "$status" != "$type" ]]; then
		if [[ "$type" != "$real_type" ]]; then
		    continue
		fi
		status="CHANGE => $status"
	    else
		local info_txt="$(grep "^SCREENER_${status}_INFO:" < $name | tail -1 | cut -d: -f2-)"
		status+="$info_txt"
	    fi
	    local stamp="$(grep -o "^SCREENER_[A-Z_]\+ [0-9]\+" < "$name" | tail -1)"
	    stamp="${stamp##* }"
	    [[ "$stamp" == "" ]] && stamp=0
	    local title="$(grep "^SCREENER_TITLE=" < "$name" | tail -1 | cut -d= -f2-)"
	    local phase="$(grep -o "PHASE [^ ]\+" < "$name" | tail -1 | awk '{ print $2; }')"
	    [[ "$phase" != "" ]] && title+=" $phase"
	    [[ "$title" != "" ]] && title="'$title'"
	    local location=""$(grep -o "^SCREENER_LOCATION=.*" < "$name" | tail -1 | cut -d= -f2-)""
	    if [[ "$location" != "" ]]; then
		title+=" ($location)"
	    fi
	    local critical_section=""$(grep -o "^SCREENER_CRITICAL=[0-9]" < "$name" | tail -1 | cut -d= -f2-)""
	    if (( critical_section )); then
		status+=" in-critical-section"
	    fi
	    echo "$stamp  $id: $title $status"
	done |\
	    sort -n |\
	    if (( show_stamp )); then
	        local stamp line
		while read stamp line; do
		    if (( stamp )); then
			stamp="$(date +"$date_format" --date="@$stamp")"
		    else
			stamp=NO_DATE
		    fi
		    echo "  $stamp $line"
		done
	    else
	        sed 's/^[0-9]\+//'
	    fi
    done
}

function screen_show
{
    local id="$1"

    local type
    for type in $status_dir_list; do
	local file="$screener_logdir/$type/$id.log"
	if [[ -s "$file" ]]; then
	    echo "========== SHOWING LOGFILE '$file'"
	    cat "$file"
	    return
	fi
    done
    echo "Sorry, no logfile for '$id' found."
}

############################################################

# screen handling

function screen_exists
{
    local id="$1"

    local session="$(screen -list | grep -o "[0-9]\+.$id" | head -1)"
    if [[ "$session" = "" ]]; then
	warn "Session '$id' not found."
	return 1
    fi
    echo "$session"
    return 0
}

function screen_resume
{
    local id="$1"
    local do_fail="${2:-fail}"
    local do_exec="${3:-1}"
    local do_attach="${4:-$do_exec}"

    local session="$(screen_exists "$id")"
    echo "Session '$session'"
    if [[ "$session" = "" ]]; then
	$do_fail "Session '$id' not found."
	return
    fi
    local opt="-r"
    if (( do_attach || force_attach )); then
	opt="-x"
    fi
    if (( do_exec )); then
	exec $screen_cmd $opt "$session"
    else
	$screen_cmd $opt "$session"
    fi
}

function screen_start
{
    local id="$1"
    local cmd="${2:-bash -i}"
    declare -g title="${3:-${title:-$id}}"

    if screen_exists "$id" 2>/dev/null; then
	$screen_cmd -ls
	fail "Cannot start new session for '$id': unique session already exists."
    fi

    local logfile="$screener_logdir/running/$id.log"
    local header="echo \"SCREENER_TITLE=${title}\""
    header+="; echo \"SCREENER_START \$(date +%s) \$(date) $id title=$title cmd=$cmd\""
    local footer="echo \"SCREENER_END \$(date +%s) \$(date)\""
    local fifo="/tmp/FIFO.$id.$$"
    local inside_cmd="set -o pipefail"
    inside_cmd+="; export LC_ALL=C"
    inside_cmd+="; export screener=0"
    inside_cmd+="; export use_screener=1"
    inside_cmd+="; export logdir=\"$screener_logdir\""
    inside_cmd+="; mkfifo $fifo"
    inside_cmd+="; tee -a $logfile < $fifo &"
    inside_cmd+="{ $header; ($cmd); rc=\$?; echo \"\"; $footer; echo \"STATUS=\$rc\""
    if (( sleep )); then
	inside_cmd+="; sleep $sleep"
    fi
    if (( drop_shell )); then
	inside_cmd+="; if (( rc )); then echo \"Dropping session \\\"$id\\\" to an interactive shell due to error code \$rc\"; bash -i; fi"
    fi
    inside_cmd+=";} 2>&1 >> $fifo"
    inside_cmd+="; sleep 1"
    inside_cmd+="; rm -f /tmp/FIFO.%id.*"
    # the logfile must be already closed before cron can work correctly
    inside_cmd+="; screener_logdir=\"$screener_logdir\" $script_dir/$(basename "$0") cron"

    local screen_opts="-S \"$id\" -t \"$title\" -d -m"
    if (( use_screenlog )); then
	screen_opts+=" -L"
    fi
    local run_cmd="$screen_cmd $screen_opts bash -c '${inside_cmd//'/\'}'"
    if (( dry_run )); then
	echo -n "WOULD do but dry_run: "
    fi
    echo "Starting screen $id '$title'"
    if (( debug )); then
	echo "$run_cmd"
    fi
    if (( !dry_run )); then
	eval "$run_cmd"
    fi
}

function screen_restart
{
    local id="$1"

    local fail_list="critical serious failed"
    local status="$(has_status "$id" "$fail_list")"
    if [[ "$status" = "" ]]; then
	fail "cannot restart '$id': not ${fail_list// /|}."
    fi
    local check="$screener_logdir/$status/$id.log"
    local title="$(grep "^SCREENER_TITLE=" < "$check" | tail -1 | cut -d= -f2-)"
    local cmd="$(grep "^SCREENER_START " < "$check" | tail -1 | cut -d= -f3-)"
    if [[ "$cmd" = "" ]]; then
	fail "cannot restart 'id': no old command found. Do this by hand!"
    fi
    echo "RESTARTING old title:   '$title'"
    echo "RESTARTING old command: '$cmd'"
    screen_start "$id" "$cmd" "$title"
    $screen_cmd -list
    if (( auto_attach )); then
	echo "Press Ctrl-C within $auto_attach_grace seconds to abort"
	sleep $auto_attach_grace
	screen_resume "$id" "warn"
    fi
}

function screen_kill
{
    local id="$1"
    local do_fail="${2:-1}"

    local session="$(screen_exists "$id")"
    if [[ "$session" = "" ]]; then
	(( do_fail )) && fail "no screen session for '$id' found."
	warn "no screen session for '$id' found."
    fi
    $screen_cmd -r "$session" -X kill
}

function screen_continue
{
    local status="$1"
    local id_list="$2"

    while true; do
	local restart=0
	# Allow numerical argument => number of sessions to resume
	if [[ "$id_list" =~ ^[0-9] ]]; then
	    id_list="$(list_status $status 0 | head -$id_list | cut -d: -f1)"
	    echo "Selected sessions:" $id_list
	elif [[ "$id_list" = "" ]]; then
	    # continue all
	    id_list="$(list_status $status 0 | cut -d: -f1)"
	fi

	local id
	for id in $id_list; do
	    local session="$(screen_exists "$id")"
	    if [[ "$session" = "" ]]; then
		(( auto_attach )) && continue
		fail "no screen session for '$id' found."
	    fi
	    local flagfile="$screener_logdir/running/$id.$status"
	    if ! [[ -e "$flagfile" ]]; then
		(( auto_attach )) && continue
		fail "flagfile '$flagfile' does not exist"
	    fi
	    echo "Removing flagfile '$flagfile'"
	    if (( auto_attach )); then
		echo "Press Ctrl-C within $auto_attach_grace seconds to abort"
		sleep $auto_attach_grace
	    fi
	    echo rm -f "$flagfile"
	    rm -f "$flagfile"
	    if (( auto_attach )); then
		sleep 1
		screen_resume "$id" warn 0
		restart=1
	    fi
	done
	(( !restart )) && return
	echo "Re-scanning sessions"
    done
}

function screen_lock
{
    local lock="$1"
    local id="$2"

    local file="$screener_logdir/lock"
    if [[ "$id" != "" ]]; then
	file+=".$id"
    fi
    if (( lock )); then
	echo "touch $file"
	touch "$file"
    else
	echo "rm -f $file"
	rm -f "$file"
    fi
}

function screen_purge
{
    local period="${1:-$screener_log_purge_period}"
    local args="${2:--ls -exec rm -f {\} +}"

    if [[ "$period" = "" ]]; then
	return
    fi
    local cmd="find \"$screener_logdir/\" -name \"*.log\" -mtime \"$period\" ${args//\\/\\\\}"
    if (( verbose )); then
	echo "$cmd"
    fi
    eval "$cmd"
}

function screen_cron
{
    {
	mkdir -p $screener_logdir
	list_status running 0
	screen_purge
    } >> "$screener_cron_log" 2>&1
}

#####################################################################

# csv filter parsing

## tmp_dir and tmp_stub
# Where temporary files are residing
tmp_dir="${tmp_dir:-/tmp}"
tmp_stub="${tmp_stub:-$tmp_dir/screener.$$}"

function filter_csv
{
    local field="$1"
    local op="$2"
    local match="$3"
    local max_per="${4:-0}"

    local tmp_file="$tmp_stub.$(basename "$csv_file").tmp"
    (
	local col=-1
	IFS="$csv_delim"
	read -a header
	for (( i = 0; i < ${#header[*]}; i++ )); do
	    if [[ "${header[$i]}" = "$field" ]]; then
		col=$i
		if (( verbose >= 2 )); then
		    echo "MATCHING_COLUMN $i '${header[$i]}'"
		fi
	    elif (( verbose >= 2 )); then
		echo "NON_MATCHING_COLUMN $i '${header[$i]}'"
	    fi
	done
	if (( col >= 0 )); then
	    echo "USING FILTER COLUMN '${header[$col]}'"
	else
	    warn "UNDEFINED / non-existing FIELD specification '$field'"
	fi
	echo "${header[*]}" > $tmp_file
	local -A counts=()
	while read -a line; do
	    local val
	    local expr
	    if (( col >= 0 )); then
		val="${line[$col]}"
		expr="[[ \"$val\" $op \"$match\" ]]"
		[[ "$op" = "=~" ]] && expr="[[ \"$val\" $op $match ]]"
	    fi
	    if (( col < 0 )) || eval "$expr"; then
		if (( col >= 0 )); then
		    (( counts[$val]++ ))
		    if (( counts[$val] > max_per && max_per > 0 )); then
			if (( verbose >= 2 )); then
			    echo "MAX_PER=$max_per exceeded at '$val' line '${line[*]}'"
			fi
			continue
		    elif (( verbose )); then
			echo "SELECTED by $op '$match': '$val' line '${line[*]}'"
		    fi
		fi
		echo "${line[*]}" >> $tmp_file
	    fi
	done
    ) < $csv_file
    echo "CSV_FILTER $field $op '$val' on '$csv_file' $(tail -n+2 < $csv_file | wc -l) lines => now $(tail -n+2 < $tmp_file | wc -l) lines"
    csv_file="$tmp_file"
}

function run_csv
{
    local id_col=-1
    local cmd_col=-1
    (
	local old_IFS="$IFS"
	IFS="$csv_delim"
	read -a header
	for (( i = 0; i < ${#header[*]}; i++ )); do
	    if [[ "${header[$i]}" =~ $csv_id_fields ]]; then
		(( id_col < 0 )) && id_col=$i
	    elif [[ "${header[$i]}" =~ $csv_cmd_fields ]]; then
		(( cmd_col < 0 )) && cmd_col=$i
	    fi
	done
	if (( id_col < 0 )); then
	    fail "Undefined screen_id colum. Adjust csv_id_fields."
	fi
	if (( cmd_col < 0 )); then
	    echo "Undefined cmd colum. Falling back to coloumn 0."
	    cmd_col=0
	fi
	local start_count=0
	while IFS="$csv_delim" read -a line; do
	    IFS="$old_IFS"
	    local id="${line[$id_col]}"
	    #id="${id//[-]/_}"
	    local cmd="${line[$cmd_col]}"
	    if [[ "$csv_remove" != "" ]]; then
		cmd="${cmd//$csv_remove/}"
	    fi
	    cmd="${cmd## }"
	    cmd="${cmd%% }"
	    if [[ "$id" = "" ]]; then
		echo "SKIPPING empty screen_id for cmd='$cmd'"
		continue
	    fi
	    local status="$(has_status "$id")"
	    if [[ "$status" != "" ]]; then
		echo "SKIPPING $id: status=$status"
		continue
	    fi
	    if (( max > 0 && start_count >= max )); then
		echo "Reached $start_count launches."
		break
	    fi
	    if screen_exists "$id" 2>/dev/null; then
		continue
	    fi
	    echo "STARTING $id '$cmd'"
	    screen_start "$id" "$cmd" "$id"
	    (( start_count++ ))
	done
	echo "TOTAL_LAUNCHES: $start_count"
    ) < $csv_file
    rm -f $tmp_stub.$(basename "$csv_file").tmp
}

#####################################################################

# main

if [[ "$op" = "" ]] || [[ "$op" =~ help ]]; then
    screen_help
    exit 0
fi

commands_installed "$screener_commands_needed"

[[ -d "$screener_logdir" ]] || fail "logdir '$screener_logdir' does not exist."

case "$op" in
run)
    shift 2
    screen_cron
    csv_file="$id"
    if ! [[ -s "$csv_file" ]]; then
	fail "CSV file '$csv_file' does not exist"
    fi
    max=${max:-0}
    max_per=0
    while [[ "$1" =~ ^-- ]]; do
	par="$1"
	shift
	if [[ "$par" =~ ^--([_a-zA-Z][_a-zA-Z0-9]*)(==|!=|=~)(.*)$ ]]; then
	    filter_csv "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "$max_per"
	    max_per=0
	else
	    parse_option "$par"
	fi
    done
    run_csv
    ;;

start)
    shift 2
    screen_cron
    screen_start "$id" "$*"
    $screen_cmd -list
    if (( auto_attach )); then
	sleep 1
	screen_resume "$id" "warn"
    fi
    ;;

restart)
    screen_cron
    screen_restart "$id"
    ;;

kill)
    screen_kill "$id"
    screen_cron
    list_screens
    ;;

continue | continue-waiting)
    shift
    screen_continue waiting "$@"
    ;;

wakeup | continue-delayed)
    shift
    screen_continue delayed "$@"
    ;;

up)
    shift
    screen_continue waiting "$@"
    screen_continue delayed "$@"
    ;;

auto)
    shift
    auto_attach=1
    screen_continue waiting "$@"
    screen_continue delayed "$@"
    ;;

resume)
    screen_resume "$id" fail 1 0
    ;;

attach)
    screen_resume "$id" fail 1 1
    ;;

list-screens)
    list_screens
    ;;

list-running)
    screen_cron
    list_status running
    ;;

list-waiting)
    list_status waiting
    ;;

list-delayed)
    list_status delayed
    ;;

list-condition)
    list_status condition
    ;;

list-failed)
    screen_cron
    list_status failed
    ;;

list-critical)
    screen_cron
    list_status critical
    ;;

list-serious)
    screen_cron
    list_status serious
    ;;

list-done)
    screen_cron
    list_status done
    ;;

list)
    screen_cron
    list_screens
    echo "List of waiting:"
    list_status waiting
    echo "List of delayed:"
    list_status delayed
    echo "List of condition:"
    list_status condition
    list_status
    ;;

notify)
    shift 2
    call_hook notify "$id" "$@"
    ;;

status)
    screen_cron
    list_status "" 0 "$id"
    ;;

show)
    screen_cron
    screen_show "$id"
    ;;

less)
    screen_cron
    screen_show "$id" | $less_cmd
    ;;

clear-failed)
    screen_cron
    change_status "$id" failed done
    ;;

clear-critical)
    screen_cron
    change_status "$id" critical done
    ;;

clear-serious)
    screen_cron
    change_status "$id" serious done
    ;;

purge)
    shift
    screen_purge "$@"
    ;;

lock)
    shift
    screen_lock 1 "$@"
    ;;

unlock)
    shift
    screen_lock 0 "$@"
    ;;

cron)
    screen_cron
    call_hook cron "$@"
    ;;

help)
    screen_help
    ;;

*)
    fail "unknown operation '$op'"
    ;;
esac
