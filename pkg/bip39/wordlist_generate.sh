#!/bin/bash
# paperback: resilient paper backups for the very paranoid
# Copyright (C) 2018 Aleksa Sarai <cyphar@cyphar.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

set -e -o pipefail

function bail() {
	echo "$@" >&2
	exit 1
}

WORDLIST="$1"
OUTPUT="$2"
[ -f "$WORDLIST" ] || bail "$WORDLIST doesn't exist or isn't a file."

NUM="$(wc -l "$WORDLIST" | awk '{ print $1 }')"

# Generate the entire wordlist.
cat >"$OUTPUT" <<EOF
/*
 * paperback: resilient paper backups for the very paranoid
 * Copyright (C) 2018 Aleksa Sarai <cyphar@cyphar.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// This file was generated with wordlist_generate.sh. DO NOT EDIT DIRECTLY

package bip39

const wordlistSize = $NUM

// wordlist is hidden to ensure that another package cannot change this
// wordlist by accident.
var wordlist = [wordlistSize]string{
$(cat "$WORDLIST" | xargs printf '\t"%q",\n')
}
EOF
