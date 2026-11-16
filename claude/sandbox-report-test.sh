#!/bin/sh
# Runs sandbox-report.sh on fixture transcripts, with a fixed clock and home, and compares its
# output with the expected report.
set -eu
cd "$(dirname "$0")"
data=testdata/sandbox-report
# 1767225600 is 2026-01-01T00:00:00Z.
actual=$(HOME=/Users/test DAYS=30 SANDBOX_REPORT_NOW=1767225600 sh sandbox-report.sh "$data/projects")
if [ "$actual" != "$(cat "$data/expected.txt")" ]; then
	printf 'sandbox-report: output differs from %s\n--- expected\n%s\n--- actual\n%s\n' \
		"$data/expected.txt" "$(cat "$data/expected.txt")" "$actual" >&2
	exit 1
fi
