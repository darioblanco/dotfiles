#!/bin/sh
# Count what the Claude Code sandbox blocked in recent sessions, to decide in one go which hosts
# or paths to allow (see the rule above the policy in home/dot_claude/modify_settings.json).
# Hosts come from each sandboxed command's sandboxViolations in the session transcripts, paths
# from "Operation not permitted" errors in sandboxed commands' output. Read-only.
#   claude/sandbox-report.sh [projects-dir]    DAYS=30 by default
set -eu
dir=${1:-$HOME/.claude/projects}
days=${DAYS:-30}
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
rows=$(rg --no-ignore --hidden -N --no-filename -F --glob '*.jsonl' \
	-e '"sandboxViolations":[{' -e 'Operation not permitted' "$dir" |
	jq -R -r --arg home "$HOME" --argjson cutoff "$((now - days * 86400))" '
	fromjson? | select(.type == "user" and .sandboxed == true)
	| select((.timestamp // "" | sub("\\.[0-9]+Z$"; "Z") | try fromdateiso8601 catch 0) >= $cutoff)
	| .sessionId as $s
	| (([.sandboxViolations[]? | select(.kind == "network") | .host] | unique[] | "host\t\(.)\t\($s)"),
	   ([.message.content[]? | select(.type == "tool_result") | .content
	     | if type == "string" then . else ([.[]? | .text? // empty] | join("\n")) end
	     | scan("(?:^|[\\s\\x27\"(=])(/[^\\s:\\x27\"]+)[\\x27\"]?: Operation not permitted") | .[0]
	     | if startswith($home + "/") then "~" + .[($home | length):] else . end
	     | split("/")[0:4] | join("/")] | unique[] | "path\t\(.)\t\($s)"))' |
	awk -F'\t' '{ k = $1 FS $2; n[k]++; if (!seen[k FS $3]++) s[k]++ }
		END { for (k in n) { split(k, a, FS); print a[1] FS n[k] FS s[k] FS a[2] } }' |
	sort -t "$tab" -k1,1 -k2,2nr -k4,4)

section() {
	printf '%s (last %s days)\ncommands  sessions  %s\n' "$2" "$days" "$1"
	printf '%s\n' "$rows" | awk -F'\t' -v kind="$1" '
		$1 == kind { printf "%8d  %8d  %s\n", $2, $3, $4; found = 1 }
		END { if (!found) print "    none" }'
}
section host "Blocked hosts"
echo
section path "Denied paths"
