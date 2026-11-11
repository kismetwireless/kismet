#!/bin/bash
# Usage: .github/ci/selftest.sh
#
# Checks the CI helpers in this directory without GitHub: the problem matcher
# against real g++ and ld output, and build-summary.jq against sample jobs.
# Needs g++ (or CXX), jq and python3; shellcheck is used if installed.

set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
fail=0

check() {
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		printf 'FAIL %s\n  want: %s\n  got:  %s\n' "$1" "$2" "$3"
		fail=1
	fi
}

cd "${tmp}"
printf 'int f() {\n  int x = 1;\n  return y;\n}\n' > compile_error.cc
printf 'int g();\nint main() { int unused; return g(); }\n' > link_error.cc
{
	"${CXX:-g++}" -Wall -c compile_error.cc || true
	"${CXX:-g++}" -Wall link_error.cc -o link_error || true
	echo "/github/workspace/capture_foo/foo.c:12:5: fatal error: foo.h: No such file or directory"
	echo "configure: error: libpcap is required"
} > log 2>&1

python3 -I - "${here}/gcc-matcher.json" log > matches <<'EOF'
import json, re, sys
matchers = json.load(open(sys.argv[1]))["problemMatcher"]
for line in open(sys.argv[2]):
    line = line.rstrip("\n")
    for m in matchers:
        p = m["pattern"][0]
        r = re.match(p["regexp"], line)
        if r:
            print(m["owner"], *(r.group(p[k]) if k in p else "-" for k in ("file", "line", "column")), r.group(p["message"]), sep="|")
EOF

check "compiler error" "kismet-compiler|compile_error.cc|3|10" \
	"$(grep -m1 '^kismet-compiler|compile_error.*y' matches | cut -d'|' -f1-4 || true)"
check "absolute path stripped" \
	"kismet-compiler|capture_foo/foo.c|12|5|foo.h: No such file or directory" \
	"$(grep -m1 '^kismet-compiler|capture_foo' matches || true)"
check "linker error" "1" "$(grep -c '^kismet-linker|.*undefined reference to .g()' matches || true)"
check "configure error" "kismet-configure|-|-|-|libpcap is required" "$(grep '^kismet-configure' matches || true)"
check "warnings ignored" "0" "$(grep -c 'unused' matches || true)"

jobs='[
 {"name":"Already tested?","conclusion":"success","html_url":"u0"},
 {"name":"Alpine / default","conclusion":"success","html_url":"u1"},
 {"name":"Alpine / all","conclusion":"failure","html_url":"u2","steps":[{"name":"Build (all)","conclusion":"failure"}]},
 {"name":"Ubuntu 24.04 / default","conclusion":"success","html_url":"u3"},
 {"name":"Ubuntu 24.04 / all","conclusion":"cancelled","html_url":"u4"},
 {"name":"Ubuntu 26.04 / default","conclusion":null,"html_url":"u5"},
 {"name":"Ubuntu 26.04 / all","conclusion":"failure","html_url":"u7","steps":[{"name":"Build (all)","conclusion":"success"},{"name":"Run kismet on 50 hwsim radios","conclusion":"failure"}]},
 {"name":"Ubuntu 24.04 / all-no-wext","conclusion":"failure","html_url":"u8"},
 {"name":"All builds","conclusion":null,"html_url":"u6"}
]'
check "summary grid" \
	"| | default | all | all-no-wext |
|---|---|---|---|
| **Alpine** | ✅ | [❌ build](u2) | ❔ |
| **Ubuntu 24.04** | ✅ | [🚫](u4) | [❌](u8) |
| **Ubuntu 26.04** | [❔](u5) | [❌ run](u7) | ❔ |" \
	"$(jq -c '.[]' <<< "${jobs}" | jq -rs -f "${here}/build-summary.jq")"

for f in "${here}"/*.sh; do
	check "syntax ${f##*/}" "" "$(bash -n "$f" 2>&1)"
done
if command -v shellcheck > /dev/null; then
	check "shellcheck" "" "$(shellcheck -e SC1091 "${here}"/*.sh 2>&1 || true)"
else
	echo "ok   shellcheck skipped (not installed)"
fi

exit "${fail}"
