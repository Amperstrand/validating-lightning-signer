#!/usr/bin/env bash
# Splice-status drift check (issue #2).
#
# Fails when docs/splice-status.md disagrees with itself: the claimed
# case count vs the case table, the pinned CLN revisions, the verdict
# headline, or the verification-log ordering. Optional external mode
# (SPLICE_STATUS_CHECK_CLN=1) also cross-checks the case names against
# the CLN fork's tests/test_splicing.py at the pinned revision.
#
# Usage: contrib/check-splice-status.sh          (internal consistency)
#        SPLICE_STATUS_CHECK_CLN=1 contrib/...   (also fetch the fork file)

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
manifest="$root/docs/splice-status.md"

fail() { echo "splice-status drift: $*" >&2; exit 1; }

[[ -f "$manifest" ]] || fail "manifest $manifest missing"

# --- extract the machine-readable TOML block -----------------------------
toml="$(awk '/^```toml$/{f=1;next} /^```$/{f=0} f' "$manifest")"
[[ -n "$toml" ]] || fail "no \`\`\`toml block found in $manifest"

key() { # key <section>.<key> -> value (quoted strings unquoted)
    local want="$1" section="" k v
    while IFS= read -r line; do
        line="${line%%#*}"
        [[ "$line" =~ ^\[.*\]$ ]] && { section="${line:1:${#line}-2}"; continue; }
        [[ "$line" == *"="* ]] || continue
        k="${line%%=*}"; k="${section}.${k//[[:space:]]/}"
        v="${line#*=}"; v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
        if [[ "$k" == "$want" ]]; then
            v="${v#\"}"; v="${v%\"}"
            printf '%s' "$v"
            return 0
        fi
    done <<< "$toml"
    fail "key $want missing from the TOML block"
}

# --- counts ---------------------------------------------------------------
verified="$(key status.verified_cases)"
total="$(key status.total_cases)"
[[ "$verified" =~ ^[0-9]+$ ]] || fail "status.verified_cases not numeric: $verified"
[[ "$total" =~ ^[0-9]+$ ]] || fail "status.total_cases not numeric: $total"
[[ "$verified" -le "$total" ]] || fail "verified_cases ($verified) > total_cases ($total)"

rows="$(grep -cE '^\| [0-9]+ \| `test_' "$manifest" || true)"
[[ "$rows" == "$total" ]] || fail "case table has $rows rows, total_cases says $total"

# sequential numbering 1..N
expected=1
while IFS= read -r n; do
    [[ "$n" == "$expected" ]] || fail "case table numbering breaks at row $n (expected $expected)"
    expected=$((expected + 1))
done < <(grep -E '^\| [0-9]+ \| `test_' "$manifest" | awk -F'|' '{gsub(/ /,"",$2); print $2}')

modes="$(key status.modes)"
grep -q '"permissive"' <<< "$modes" || fail "modes missing permissive"
grep -q '"strict"' <<< "$modes" || fail "modes missing strict"

# --- headline agreement ----------------------------------------------------
headline="$(grep -m1 -oE '\*\*[0-9]+ of [0-9]+ CLN splice-suite cases green\*\*' "$manifest" || true)"
[[ -n "$headline" ]] || fail "verdict headline missing/malformed"
[[ "$headline" == "**$verified of $total CLN splice-suite cases green**" ]] \
    || fail "headline '$headline' disagrees with TOML ($verified/$total)"

# --- revisions --------------------------------------------------------------
delivery_commit="$(key status.delivery_commit)"
[[ "$delivery_commit" =~ ^[0-9a-f]{40}$ ]] || fail "delivery_commit not a 40-hex sha: $delivery_commit"

fork_repo="$(key cln.fork_repo)"
fork_branch="$(key cln.fork_branch)"
suite_file="$(key cln.suite_file)"
strict_rev="$(key cln.strict_verified_revision)"
[[ "$strict_rev" =~ ^[0-9a-f]{8,40}$ ]] || fail "strict_verified_revision not a sha: $strict_rev"
[[ -n "$fork_repo" && -n "$fork_branch" && -n "$suite_file" ]] || fail "cln fork pin incomplete"

delivery_rev="$(key cln.delivery_revision)"
[[ -n "$delivery_rev" ]] || fail "cln.delivery_revision empty"

# --- verification log ordering ----------------------------------------------
prev=""
while IFS= read -r d; do
    [[ "$d" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fail "verification_log date malformed: $d"
    [[ -z "$prev" || "$d" > "$prev" ]] || fail "verification_log not oldest-first at $d"
    prev="$d"
done < <(awk '/^\[verification_log\]/{f=1;next} /^\[/{f=0} f && /^[0-9]{4}-/ {print $1}' <<< "$toml")

last_log="$(awk '/^\[verification_log\]/{f=1;next} /^\[/{f=0} f && /^[0-9]{4}-/ {print $1}' <<< "$toml" | tail -1)"
last_strict="$(key status.last_strict_verified)"
[[ "$last_log" == "$last_strict" ]] \
    || fail "newest verification_log row ($last_log) != status.last_strict_verified ($last_strict)"

# --- optional external cross-check -----------------------------------------
if [[ "${SPLICE_STATUS_CHECK_CLN:-0}" == "1" ]]; then
    url="https://raw.githubusercontent.com/$fork_repo/$strict_rev/$suite_file"
    remote="$(curl -fsSL "$url" 2>/dev/null)" || fail "could not fetch $url (bad pin or network)"

    table_cases() { grep -E '^\| [0-9]+ \| `test_' "$manifest" | awk -F'`' '{print $2}'; }
    remote_cases() { grep -oE 'def test_[A-Za-z0-9_]+\(' <<< "$remote" | sed 's/^def //; s/($//'; }

    # unique-set comparison, both directions (issue #20): the old
    # per-entry grep accepted any SUBSET of the remote suite — a pinned
    # revision that ADDED splice cases, or a duplicated table row
    # covering an omitted one, passed silently.
    dup_cases="$(table_cases | sort | uniq -d)"
    [[ -z "$dup_cases" ]] \
        || fail "duplicate case rows in the table: $(echo "$dup_cases" | tr '\n' ' ')"

    only_table="$(table_cases | sort -u | comm -23 - <(remote_cases | sort -u))"
    [[ -z "$only_table" ]] \
        || fail "cases in the table but missing from $fork_repo@$strict_rev:$suite_file — pin drifted: $(echo "$only_table" | tr '\n' ' ')"

    only_remote="$(table_cases | sort -u | comm -13 - <(remote_cases | sort -u))"
    [[ -z "$only_remote" ]] \
        || fail "splice cases defined in $fork_repo@$strict_rev:$suite_file but absent from the table: $(echo "$only_remote" | tr '\n' ' ')"

    unique_rows="$(table_cases | sort -u | wc -l)"
    echo "external check: $unique_rows unique cases match $fork_repo@$strict_rev exactly (both directions)"
fi

echo "splice-status OK: $verified/$total cases, CLN $delivery_rev -> $fork_repo/$fork_branch@$strict_rev, table+log consistent"
