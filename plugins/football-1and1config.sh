#!/bin/bash
#
# This file is part of MARS project: http://schoebel.github.io/mars/
#
# Copyright (C) 2018 Stefan Noll
# Copyright (C) 2017 Thomas Schoebel-Theuer
# Copyright (C) 2018 1&1 Internet AG
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

# 1&1 specific plugin / hooks for working with Jessie icpu conventions and cm3
#
# This script must be sourced from the main script.

# Guard agains multiple sourcing
[[ "${files[1and1config]}" != "" ]] && return

function 1and1config_describe_plugin
{
    cat <<EOF

PLUGIN football-1and1config

   1&1 specfic plugin for dealing with the cm3 clusters
   and its concrete configuration.

EOF
   show_vars "${files[1and1config]}"
}

register_description "1and1config"

###########################################

## enable_1and1config
# ShaHoLin-specifc plugin for working with the infong platform
# (istore, icpu, infong) via 1&1-specific clustermanager cm3
# and related toolsets. Much of it is bound to a singleton database
# instance (clustermw & siblings).
enable_1and1config="${enable_1and1config:-$(if [[ "$0" =~ tetris ]]; then echo 1; else echo 0; fi)}"

(( enable_1and1config )) || return 0

commands_installed "ssh"

function 1and1config_runstack
{
    local source="$1"
    local target="$2"
    local res="$3"

    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return
    [[ "$res" = "" ]] && return

    local source_cluster="$(_get_cluster_name "$source")" || fail "cannot get source_cluster"
    local target_cluster="$(_get_cluster_name "$target")" || fail "cannot get target_cluster"

    if (( always_migrate )) || [[ "$source_cluster" != "$target_cluster" ]]; then
		echo "Call runstack for deploying cluster config for example /etc/1und1/cm-infong.conf to '$res' in cluster '$target_cluster'"

		local cmd="apply cluster/clusterconfig.git:master -- cluster $target_cluster -l $res "

		remote "runstack@runstack.schlund.de" "$cmd "
	fi
}


function 1and1config_dastool
{
    local source="$1"
    local target="$2"
    local res="$3"

    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return
    [[ "$res" = "" ]] && return

    local source_cluster="$(_get_cluster_name "$source")" || fail "cannot get source_cluster"
    local target_cluster="$(_get_cluster_name "$target")" || fail "cannot get target_cluster"

    if (( always_migrate )) || [[ "$source_cluster" != "$target_cluster" ]]; then
		echo "Call dastool for deploying cluster config for example /etc/1und1/infong.conf to '$res' "

		local cmd="/home/spacetools/bin/dastool $res.schlund.de "

		remote "spacetools@dastool6.schlund.de " "$cmd "
	fi
}


function 1and1config_update_action
{
    local res="$1"

    [[ "$res" = "" ]] && return

    if (( always_migrate )); then
		echo "Call efficiency_update_resource_automat.pl for '$res' "

		local cmd="/home/infongstats/bin/efficiency_update_resource_automat.pl --resource $1 --commit "

		remote "root@bkstool.schlund.de " "$cmd "
	fi
}

register_module "1and1config"