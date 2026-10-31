#!/usr/bin/env bash
# Regression tests for check-splice-status.sh's external cross-check
# (issue #20): the unique-set comparison must catch drift in BOTH
# directions — remote-added cases and table-side omissions/duplicates —
# not just table entries missing from the remote file.
#
# Runs the real checker against a fixture manifest with a PATH-stubbed
# curl, so no network is touched. Exits nonzero on any regression.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/fixture/docs" "$tmp/fixture/contrib" "$tmp/bin"
cp "$repo_root/contrib/check-splice-status.sh" "$tmp/fixture/contrib/"

# The stub "remote" suite file contents are selected per case below.
cat > "$tmp/bin/curl" <<'STUB'
#!/usr/bin/env bash
# fixture stub for the pinned remote suite file
cat "$REMOTE_FIXTURE_FILE"
STUB
chmod +x "$tmp/bin/curl"
export REMOTE_FIXTURE_FILE="$tmp/remote.py"

write_manifest() { # write_manifest <row2-case>  (row 1 is always test_splice_one)
    local row2="$1"
    cat > "$tmp/fixture/docs/splice-status.md" <<MANIFEST
# fixture

**2 of 2 CLN splice-suite cases green**

\`\`\`toml
[status]
verified_cases = 2
total_cases = 2
modes = ["permissive", "strict"]
last_delivered = 2026-01-01
last_strict_verified = 2026-01-02
delivery_commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[cln]
delivery_revision = "v26.06.6"
fork_repo = "fixture/fork"
fork_branch = "fixture-branch"
strict_verified_revision = "bbbbbbbb"
suite_file = "tests/test_fixture.py"

[vls]
branch = "fixture-branch"

[verification_log]
2026-01-01 = "first"
2026-01-02 = "second"
\`\`\`

| 1 | \`test_splice_one\` | 2026-01-01 | 2026-01-02 |
| 2 | \`${row2}\` | 2026-01-01 | 2026-01-02 |
MANIFEST
}

write_remote() { # write_remote <defs...>
    : > "$tmp/remote.py"
    local def
    for def in "$@"; do
        printf '    def %s(self, node):\n        pass\n' "$def" >> "$tmp/remote.py"
    done
}

expect_ok() { # expect_ok <label>
    local label="$1" out
    if out="$(PATH="$tmp/bin:$PATH" SPLICE_STATUS_CHECK_CLN=1 \
        "$tmp/fixture/contrib/check-splice-status.sh" 2>&1)"; then
        echo "PASS (accepted): $label"
    else
        echo "FAIL: $label must be accepted, was rejected:" >&2
        echo "$out" >&2
        exit 1
    fi
}

expect_reject() { # expect_reject <label> <expected-stderr-snippet>
    local label="$1" snippet="$2" out
    if out="$(PATH="$tmp/bin:$PATH" SPLICE_STATUS_CHECK_CLN=1 \
        "$tmp/fixture/contrib/check-splice-status.sh" 2>&1)"; then
        echo "FAIL: $label must be rejected, was accepted" >&2
        exit 1
    elif ! grep -qF "$snippet" <<< "$out"; then
        echo "FAIL: $label rejected with the wrong diagnosis:" >&2
        echo "$out" >&2
        exit 1
    else
        echo "PASS (rejected): $label"
    fi
}

# 1. exact match (both directions equal) — accepted
write_manifest "test_splice_two"
write_remote "test_splice_one" "test_splice_two"
expect_ok "exact table/remote match"

# 2. the remote ADDED a splice case the table doesn't list — rejected
#    (the old subset-only check accepted this)
write_remote "test_splice_one" "test_splice_two" "test_splice_new"
expect_reject "remote-added case" "absent from the table"

# 3. a table case is missing from the remote file — rejected (pre-existing behavior)
write_manifest "test_splice_two"
write_remote "test_splice_one" "test_splice_other"
expect_reject "table case missing remotely" "pin drifted"

# 4. a DUPLICATED table row covering an omitted one — rejected
#    (the old check passed as long as each listed name existed remotely)
write_manifest "test_splice_one"
write_remote "test_splice_one" "test_splice_two"
expect_reject "duplicated table row" "duplicate case rows"

echo "check-splice-status external cross-check: all fixture cases behave"
