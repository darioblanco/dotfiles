#!/bin/sh
# Count what the Claude Code sandbox blocked in recent sessions, to decide in one go which hosts
# or paths to allow (see the rule above the policy in home/dot_claude/modify_settings.json).
# Hosts come from each sandboxed command's sandboxViolations in the session transcripts, paths
# from "Operation not permitted" errors in sandboxed commands' output. Read-only.
#   claude/sandbox-report.sh [projects-dir]    DAYS=30 by default
set -eu
# pipefail, so a failing rg or jq isn't read as "none".
# shellcheck disable=SC3040 # POSIX since 2024; macOS sh (bash) and dash have it
set -o pipefail
for tool in rg jq; do
	command -v "$tool" >/dev/null || {
		echo "sandbox-report: needs $tool (brew bundle --file=Brewfile)" >&2
		exit 1
	}
done
dir=${1:-$HOME/.claude/projects}
days=${DAYS:-30}
case $days in '' | *[!0-9]*)
	echo "sandbox-report: DAYS must be a number of days" >&2
	exit 1
	;;
esac
[ -d "$dir" ] || {
	echo "sandbox-report: no such directory: $dir" >&2
	exit 1
}
# The clock can be fixed for tests.
now=${SANDBOX_REPORT_NOW:-$(date +%s)}
tab=$(printf '\t')

# Only lines that mention a block reach jq. Each line is one transcript record; lines that
# aren't valid JSON (a session still writing) are skipped. Each record yields one row per host or
# path: kind, value, session.
# shellcheck disable=SC2016 # jq variables, not shell
# ripgrep scans gigabytes of transcripts in under a second, where BSD grep takes a minute.
# rg exits 1 when nothing matches, which is a clean result.
rows=$({ rg --no-ignore --hidden -N --no-filename -F --glob '*.jsonl' \
	-e '"sandboxViolations":[{' -e 'Operation not permitted' "$dir" || [ $? -eq 1 ]; } |
	jq -R -r --arg home "$HOME" --argjson cutoff "$((now - days * 86400))" '
	fromjson? | select(.type == "user" and .sandboxed == true)
	| select((.timestamp // "" | sub("\\.[0-9]+Z$"; "Z") | try fromdateiso8601 catch 0) >= $cutoff)
	| .sessionId as $s
	| (([.sandboxViolations[]? | select(.kind == "network") | .host] | unique[] | "host\t\(.)\t\($s)"),
	   ([.message.content[]? | select(.type == "tool_result") | .content
	     | if type == "string" then . else ([.[]? | .text? // empty] | join("\n")) end
	     | scan("(?:^|[\\s\\x27\"(=])(/[^\\n:\\x27\"]+)[\\x27\"]?: Operation not permitted") | .[0]
	     # Paths may hold spaces (Application Support), so the match can start at an earlier
	     # argument ("ln -sf /a /b"): keep what follows the last " /".
	     | split(" /")[-1] | if startswith("/") then . else "/" + . end
	     | if startswith($home + "/") then "~" + .[($home | length):] else . end
	     # Per-user temp folders and file descriptors have random names; group them.
	     | if test("^/(var/folders|private/var/folders|dev/fd)/") then split("/")[0:3] else split("/")[0:4] end
	     | join("/")] | unique[] | "path\t\(.)\t\($s)"))' |
	awk -F'\t' '{ k = $1 FS $2; n[k]++; if (!seen[k FS $3]++) s[k]++ }
		END { for (k in n) { split(k, a, FS); print a[1] FS n[k] FS s[k] FS a[2] } }' |
	LC_ALL=C sort -t "$tab" -k1,1 -k2,2nr -k4,4)

section() {
	printf '%s (last %s days)\ncommands  sessions  %s\n' "$2" "$days" "$1"
	printf '%s\n' "$rows" | awk -F'\t' -v kind="$1" '
		$1 == kind { printf "%8d  %8d  %s\n", $2, $3, $4; found = 1 }
		END { if (!found) print "    none" }'
}
section host "Blocked hosts"
echo
section path "Denied paths, by the sandbox or by macOS"
