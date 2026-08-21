#!/bin/bash

# Local test for vault-sync --to-file and --from-file. Requires installed vault.

set -e -o pipefail

: ${VAULT_SYNC_BINARY:="cargo run --"}

VAULT_VERSION="$(vault version)"
echo "$VAULT_VERSION"

VAULT_ARGS=(
  server
  -dev
  -dev-root-token-id=unsafe-root-token
)

export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_SYNC_SRC_TOKEN=unsafe-root-token
export VAULT_SYNC_DST_TOKEN=unsafe-root-token

CONFIG=/tmp/vault-sync-file.yaml
INPUT=/tmp/vault-sync-input.json
EXPECTED=/tmp/vault-sync-expected.json
OUTPUT=/tmp/vault-sync-output.json

vault "${VAULT_ARGS[@]}" &> vault.log &
echo $! > vault.pid

function cleanup() {(
  set -e
  if [[ -f vault.pid ]]; then
    kill $(<vault.pid) || true
    rm -f vault.pid
  fi
  rm -f $CONFIG $INPUT $EXPECTED $OUTPUT
)}

trap cleanup EXIT

# Make sure Vault is running
while ! vault token lookup; do sleep 1; done

function write_config {
  local src_backend=$1
  local dst_backend=$2
  local src_prefix=$3
  local dst_prefix=$4

  cat <<EOF > $CONFIG
id: vault-sync
full_sync_interval: 60
src:
  url: http://127.0.0.1:8200/
  backend: $src_backend
  prefix: $src_prefix
dst:
  url: http://127.0.0.1:8200/
  backend: $dst_backend
  prefix: $dst_prefix
EOF
}

# Imports $INPUT to Vault, modifies the imported secrets, exports them back to $OUTPUT,
# then compares $OUTPUT with $EXPECTED.
#
# Every test uses its own secret engine, so it starts with an empty one.
# The secrets are imported to "$dst_prefix" and exported from "$src_prefix", "$secret_path" is
# where the imported secrets are expected to be in Vault (it is "$dst_prefix" plus the path
# the secrets have in $INPUT).
# The backend is the one the secrets have in $INPUT, "$dst_backend" is the backend they are
# imported to, by default the same one.
function run_test {(
  local title=$1
  local backend=$2
  local src_prefix=$3
  local dst_prefix=$4
  local secret_path=$5
  local dst_backend=${6:-$backend}

  echo "### $title"

  vault secrets enable -version=2 -path=$backend kv
  if [[ $dst_backend != $backend ]]; then
    vault secrets enable -version=2 -path=$dst_backend kv
  fi

  # The secrets are stored in the file under the source backend name, the import maps it to the
  # destination backend
  write_config $backend $dst_backend "$src_prefix" "$dst_prefix"

  rm -f $OUTPUT
  $VAULT_SYNC_BINARY --config $CONFIG --from-file $INPUT

  # The secrets are imported to the destination backend and prefix
  if ! vault kv get -mount $dst_backend "${secret_path}one" | grep -qE '^foo\s+bar$'; then
    echo "Secret ${secret_path}one is not imported to $dst_backend"
    exit 1
  fi
  if ! vault kv get -mount $dst_backend "${secret_path}nested/four" | grep -qE '^foo\s+bar$'; then
    echo "Secret ${secret_path}nested/four is not imported to $dst_backend"
    exit 1
  fi
  if [[ $dst_backend != $backend ]] && vault kv list -mount $backend / &> /dev/null; then
    echo "Secrets are imported to $backend instead of $dst_backend"
    exit 1
  fi

  # Add a new secret, update an existing one, delete another one. The deleted secret is still
  # listed by Vault, but it is not exported.
  vault kv put -mount $dst_backend "${secret_path}five" foo=bar
  vault kv put -mount $dst_backend "${secret_path}two" foo=baz
  vault kv delete -mount $dst_backend "${secret_path}three"

  # The export reads the backend the secrets were imported to
  write_config $dst_backend $backend "$src_prefix" "$dst_prefix"

  $VAULT_SYNC_BINARY --config $CONFIG --to-file $OUTPUT

  cat $OUTPUT

  if ! diff <(jq -S . $EXPECTED) <(jq -S . $OUTPUT); then
    echo "FAILED: $title"
    exit 1
  fi
)}

# Test 1: no prefixes, the secrets are imported to and exported from the root of the backend.

cat <<EOF > $INPUT
{
  "test1": {
    "one": {"foo": "bar"},
    "two": {"foo": "bar"},
    "three": {"foo": "bar"},
    "nested/four": {"foo": "bar"}
  }
}
EOF

cat <<EOF > $EXPECTED
{
  "test1": {
    "one": {"foo": "bar"},
    "two": {"foo": "baz"},
    "five": {"foo": "bar"},
    "nested/four": {"foo": "bar"}
  }
}
EOF

run_test "Test 1: no prefixes" test1 "" "" ""

# Test 2: src.prefix only. The secrets are imported to the root of the backend, the paths in
# $INPUT put them under "src", so the export finds them and strips "src/" from the paths.

cat <<EOF > $INPUT
{
  "test2": {
    "src/one": {"foo": "bar"},
    "src/two": {"foo": "bar"},
    "src/three": {"foo": "bar"},
    "src/nested/four": {"foo": "bar"}
  }
}
EOF

cat <<EOF > $EXPECTED
{
  "test2": {
    "one": {"foo": "bar"},
    "two": {"foo": "baz"},
    "five": {"foo": "bar"},
    "nested/four": {"foo": "bar"}
  }
}
EOF

run_test "Test 2: src.prefix" test2 "src" "" "src/"

# Test 3: dst.prefix only. The secrets are imported to "dst", the export starts from the root of
# the backend, so the exported paths include "dst/".

cat <<EOF > $INPUT
{
  "test3": {
    "one": {"foo": "bar"},
    "two": {"foo": "bar"},
    "three": {"foo": "bar"},
    "nested/four": {"foo": "bar"}
  }
}
EOF

cat <<EOF > $EXPECTED
{
  "test3": {
    "dst/one": {"foo": "bar"},
    "dst/two": {"foo": "baz"},
    "dst/five": {"foo": "bar"},
    "dst/nested/four": {"foo": "bar"}
  }
}
EOF

run_test "Test 3: dst.prefix" test3 "" "dst" "dst/"

# Test 4: both prefixes. The secrets are imported to "dst", the paths in $INPUT put them under
# "dst/src", which is where the export starts from.

cat <<EOF > $INPUT
{
  "test4": {
    "src/one": {"foo": "bar"},
    "src/two": {"foo": "bar"},
    "src/three": {"foo": "bar"},
    "src/nested/four": {"foo": "bar"}
  }
}
EOF

cat <<EOF > $EXPECTED
{
  "test4": {
    "one": {"foo": "bar"},
    "two": {"foo": "baz"},
    "five": {"foo": "bar"},
    "nested/four": {"foo": "bar"}
  }
}
EOF

run_test "Test 4: src.prefix and dst.prefix" test4 "dst/src" "dst" "dst/src/"

# Test 5: the backend in the file is not the backend the secrets are imported to. The file stores
# the secrets under the source backend name "test51", which the configuration maps to the
# destination backend "test52".

cat <<EOF > $INPUT
{
  "test51": {
    "one": {"foo": "bar"},
    "two": {"foo": "bar"},
    "three": {"foo": "bar"},
    "nested/four": {"foo": "bar"}
  }
}
EOF

cat <<EOF > $EXPECTED
{
  "test52": {
    "one": {"foo": "bar"},
    "two": {"foo": "baz"},
    "five": {"foo": "bar"},
    "nested/four": {"foo": "bar"}
  }
}
EOF

run_test "Test 5: different backend name" test51 "" "" "" test52

echo "All tests passed"
