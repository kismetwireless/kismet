# Input: the run's jobs (jq -s over the jobs API). Output: a markdown grid of
# the "<distro> / <build>" jobs, failed cells linking to their logs.

def icon: {success: "✅", failure: "❌", cancelled: "🚫", skipped: "⏭"}[. // ""] // "❔";
def ordered: reduce .[] as $x ([]; if any(.[]; . == $x) then . else . + [$x] end);

[.[] | select(.name | test(" / ")) | (.name | split(" / ")) as [$d, $b]
  | {d: $d, b: $b, c: .conclusion, u: .html_url}] as $jobs
| ($jobs | map(.d) | ordered) as $distros
| ($jobs | map(.b) | ordered) as $builds
| "| | " + ($builds | join(" | ")) + " |",
  "|---|" + ($builds | map("---") | join("|")) + "|",
  ($distros[] as $d | "| **\($d)** | " + ([$builds[] as $b
    | ([$jobs[] | select(.d == $d and .b == $b)][0] // {c: null}) as $j
    | if $j.c == "success" or $j.u == null then ($j.c | icon) else "[\($j.c | icon)](\($j.u))" end]
    | join(" | ")) + " |")
