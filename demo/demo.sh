#!/usr/bin/env bash
ARGS=("$@"); ARGC=$#; _TOPDIR=$(dirname `realpath $0`);

ARG_HELP_ARR=(
	'server-n'  'Run NOISE_N server'
	'client-n'  'Run NOISE_N client'
	'---------' '-------------------'
	'server-kk' 'Run NOISE_KK server'
	'client-kk' 'Run NOISE_KK client'
	'---------' '-------------------'
	'server-xx' 'Run NOISE_XX server'
	'client-xx' 'Run NOISE_XX client'
);

init_keys() {
! [[ -f keys.db ]] && do_warn "Generating client/server keyspairs" && ./keygen.py;
}

main() {
local _a1="${ARGS[@]::1}";

init_keys;

_valid=0;
_name="";

case "$_a1" in
	"server-n") _valid=1; _name="$_a1";;
	"client-n") _valid=1; _name="$_a1";;
	"server-kk") _valid=1; _name="$_a1";;
	"client-kk") _valid=1; _name="$_a1";;
	"server-xx") _valid=1; _name="$_a1";;
	"client-xx") _valid=1; _name="$_a1";;
	*) _valid=0; _name="invalid";;
esac

if [[ $_valid -eq 1 ]]; then
	echo "Init $_name..";
	python3 runner.py "$_name";
	exit $?;
else
	echo "Invalid/missing argument. Usage:";
	print_help "ARG_HELP_ARR";
	exit 1;
fi
}

print_help() { printf "\nAvailable args:\n";
local m; local n; local a; typeset -n a=$1; ((n=${#a[@]},m=n-1)); for ((i=0;i<=m;i++)); do
printf ' * '; paint 'ylw' "${a[i]}"; ((i++)); printf " - %s\n" "${a[((i))]}"; done; echo;
}

################################################################################
_pmod=0;
paint() { local c=1; case "$1" in "nrm") c=0;; "gry") c=30;; "red") c=31;; "grn") c=32;; "ylw") c=33;; "blu") c=34;; "pur") c=35;; "aqu") c=36;; "wht") c=1;; esac; printf "\\033[$_pmod;$c""m$2""\033[m"; };
lpaint() { local c=1; case "$1" in "nrm") c=0;; "gry") c=90;; "red") c=91;; "grn") c=92;; "ylw") c=93;; "blu") c=94;; "pur") c=95;; "aqua") c=96;; "wht") c=97;; *);; esac; printf "\\033[$_pmod;$c""m$2""\033[m"; };
paintln() { paint "$1" "$2\n"; }; lpaintln() { lpaint "$1" "$2\n"; };
painthi() { _pmod=7; paint "$1" "$2"; }; painthiln() { _pmod=7; paintln "$1" "$2"; };
lpainthi() { _pmod=7; lpaint "$1" "$2"; }; lpainthiln() { _pmod=7; lpaintln "$1" "$2"; };
do_warn() { paint 'ylw' '[WARN]'; printf ' %s\n' "$1"; }; do_error() { lpaint 'red' '[ERROR]'; printf ' %s\n' "$1"; };
do_okay() { lpaint 'grn' '[OKAY]'; printf ' %s\n' "$1"; }; do_debug() { lpaint 'blu' '[DEBUG]'; printf " $1\n"; };
should_exit() { if ! [[ $1 -eq 0 ]]; then paint 'red' '[FATAL]'; printf " Got $1"; exit $1; fi }
should_warn() { if ! [[ $1 -eq 0 ]]; then paint 'ylw' '[WARN]'; printf "Got: $1"; return 1; else return 0; fi; }
################################################################################

main;

exit 0;
