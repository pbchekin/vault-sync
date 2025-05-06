#!/bin/bash

# Local test.
# Requires installed vault.
# TODO: use vault container instead of locally installed vault.

set -e -o pipefail

: ${VAULT_SYNC_BINARY:="cargo run --"}

vault server -dev -dev-root-token-id=unsafe-root-token &> vault.log &
echo $! > vault.pid

function cleanup() {(
  set -e
  if [[ -f vault.pid ]]; then
    kill $(<vault.pid) || true
    rm -f vault.pid
  fi
  if [[ -f vault-sync.pid ]]; then
    kill $(<vault-sync.pid) || true
    rm -f vault-sync.pid
  fi
)}

trap cleanup EXIT

export VAULT_ADDR='http://127.0.0.1:8200'

# Make sure Vault is running
while ! vault token lookup; do sleep 1; done

# Enable AppRole auth method
vault auth enable approle

vault secrets enable -version=1 -path=secret1 kv
vault secrets enable -version=2 -path=secret2 kv
vault secrets enable -version=2 -path=secret11 kv
vault secrets enable -version=2 -path=secret12 kv
vault secrets enable -version=2 -path=secret21 kv
vault secrets enable -version=2 -path=secret22 kv

vault secrets list

# Check all secret engines are enabled
vault secrets list | grep -qE '^secret/\s+kv'
vault secrets list | grep -qE '^secret1/\s+kv'
vault secrets list | grep -qE '^secret2/\s+kv'
vault secrets list | grep -qE '^secret11/\s+kv'
vault secrets list | grep -qE '^secret12/\s+kv'
vault secrets list | grep -qE '^secret21/\s+kv'
vault secrets list | grep -qE '^secret22/\s+kv'

# Create reader policy
cat <<EOF | vault policy write vault-sync-reader -
  # Default secret backend "secret" (kv version 2)
  path "secret/data/*" {
    capabilities = ["read", "list"]
  }
  path "secret/metadata/*" {
    capabilities = ["read", "list"]
  }

  # Custom secret backend "secret1" (kv version 1)
  path "secret1/*" {
    capabilities = ["read", "list"]
  }

  # Custom secret backend "secret2" (kv version 2)
  path "secret2/data/*" {
    capabilities = ["read", "list"]
  }
  path "secret2/metadata/*" {
    capabilities = ["read", "list"]
  }
EOF

# Create writer policy
cat <<EOF | vault policy write vault-sync-writer -
  # Default secret backend "secret" (kv version 2)
  path "secret/data/*" {
    capabilities = ["create", "read", "update", "delete"]
  }

  # Custom secret backend "secret1" (kv version 1)
  path "secret1/*" {
    capabilities = ["create", "read", "update", "delete"]
  }

  # Custom secret backend "secret2" (kv version 2)
  path "secret2/data/*" {
    capabilities = ["create", "read", "update", "delete"]
  }
EOF

# Create new AppRoles
vault write auth/approle/role/vault-sync-reader token_policies=vault-sync-reader
vault write auth/approle/role/vault-sync-writer token_policies=vault-sync-writer

cat <<EOF > /tmp/vault-sync-token.env
export VAULT_SYNC_SRC_TOKEN=unsafe-root-token
export VAULT_SYNC_DST_TOKEN=unsafe-root-token
EOF

cat <<EOF > /tmp/vault-sync-app-role.env
export VAULT_SYNC_SRC_ROLE_ID=$(vault read auth/approle/role/vault-sync-reader/role-id -format=json | jq -r .data.role_id)
export VAULT_SYNC_SRC_SECRET_ID=$(vault write -f auth/approle/role/vault-sync-reader/secret-id -format=json | jq -r .data.secret_id)
export VAULT_SYNC_DST_ROLE_ID=$(vault read auth/approle/role/vault-sync-writer/role-id -format=json | jq -r .data.role_id)
export VAULT_SYNC_DST_SECRET_ID=$(vault write -f auth/approle/role/vault-sync-writer/secret-id -format=json | jq -r .data.secret_id)
EOF

function test_token {(
  local src_backend=$1
  local dst_backend=${2:-$src_backend}
  local secret_name=test-$RANDOM

  vault kv put -mount $src_backend ${src_prefix}${secret_name} foo=bar

  source /tmp/vault-sync-token.env
  $VAULT_SYNC_BINARY --config /tmp/vault-sync.yaml --once
  vault kv get -mount $dst_backend ${dst_prefix}${secret_name}
  vault kv get -mount $dst_backend ${dst_prefix}${secret_name} | grep -qE '^foo\s+bar$'
)}

function test_app_role {(
  local src_backend=$1
  local dst_backend=${2:-$src_backend}
  local secret_name=test-$RANDOM

  vault kv put -mount $src_backend ${src_prefix}${secret_name} foo=bar

  source /tmp/vault-sync-app-role.env
  $VAULT_SYNC_BINARY --config /tmp/vault-sync.yaml --once
  vault kv get -mount $dst_backend ${dst_prefix}${secret_name}
  vault kv get -mount $dst_backend ${dst_prefix}${secret_name} | grep -qE '^foo\s+bar$'
)}

function test_token_with_audit_device {(
  local src_backend=$1
  local dst_backend=${2:-$src_backend}
  local secret_name=test-$RANDOM
  local audit_device_name=vault-sync-$src_backend-$dst_backend

  source /tmp/vault-sync-token.env

  vault kv put -mount $src_backend ${src_prefix}${secret_name}-1 foo=bar

  $VAULT_SYNC_BINARY --config /tmp/vault-sync.yaml &
  echo $! > vault-sync.pid

  echo Wating for vault-sync to start and make the initial sync ...
  VAULT_SYNC_READY=""
  for i in 1 2 3 4 5; do
    if vault kv get -mount $dst_backend ${dst_prefix}${secret_name}-1 2> /dev/null; then
      vault kv get -mount $dst_backend ${dst_prefix}${secret_name}-1 | grep -qE '^foo\s+bar$'
      VAULT_SYNC_READY="true"
      break
    fi
    sleep 1
  done
  if [[ ! $VAULT_SYNC_READY ]]; then
    echo "vault-sync failed to start with audit device"
    exit 1
  fi

  # Enable audit device that sends log to vault-sync
  vault audit enable -path $audit_device_name socket socket_type=tcp address=127.0.0.1:8202

  vault kv put -mount $src_backend ${dst_prefix}${secret_name}-2 foo=bar

  echo Wating for vault-sync to sync on event ...
  VAULT_SYNC_READY=""
  for i in 1 2 3 4 5; do
    if vault kv get -mount $dst_backend ${dst_prefix}/${secret_name}-2 2> /dev/null; then
      vault kv get -mount $dst_backend ${dst_prefix}/${secret_name}-2 | grep -qE '^foo\s+bar$'
      VAULT_SYNC_READY="true"
      break
    fi
    sleep 1
  done
  if [[ ! $VAULT_SYNC_READY ]]; then
    echo "vault-sync failed to sync on the event from the audit device"
    exit 1
  fi

  vault audit disable $audit_device_name

  kill $(<vault-sync.pid)
  rm vault-sync.pid
)}

function test_multiple_backends {(
  local secret_name=test-$RANDOM
  local audit_device_name=vault-sync

  source /tmp/vault-sync-token.env

  vault kv put -mount secret11 ${secret_name}-1 foo=bar
  vault kv put -mount secret12 ${secret_name}-1 foo=bar

  $VAULT_SYNC_BINARY --config /tmp/vault-sync.yaml &
  echo $! > vault-sync.pid

  echo Wating for vault-sync to start and make the initial sync ...
  VAULT_SYNC_READY1=""
  VAULT_SYNC_READY2=""
  for i in 1 2 3 4 5; do
    if vault kv get -mount secret21 ${secret_name}-1 &> /dev/null; then
      vault  kv get -mount secret21 ${secret_name}-1 | grep -qE '^foo\s+bar$'
      VAULT_SYNC_READY1="true"
    fi
    if vault kv get -mount secret22 ${secret_name}-1 &> /dev/null; then
      vault  kv get -mount secret22 ${secret_name}-1 | grep -qE '^foo\s+bar$'
      VAULT_SYNC_READY2="true"
    fi
    sleep 1
  done
  if [[ ! $VAULT_SYNC_READY1 || ! $VAULT_SYNC_READY1 ]]; then
    echo "vault-sync failed to start with audit device"
    exit 1
  fi

  # Enable audit device that sends log to vault-sync
  vault audit enable -path $audit_device_name socket socket_type=tcp address=127.0.0.1:8202

  vault kv put -mount secret11 ${secret_name}-2 foo=bar
  vault kv put -mount secret12 ${secret_name}-2 foo=bar

  echo Wating for vault-sync to sync on event ...
  VAULT_SYNC_READY1=""
  VAULT_SYNC_READY2=""
  for i in 1 2 3 4 5; do
    if vault kv get -mount secret21 ${secret_name}-2 &> /dev/null; then
      vault  kv get -mount secret21 ${secret_name}-2 | grep -qE '^foo\s+bar$'
      VAULT_SYNC_READY1="true"
    fi
    if vault kv get -mount secret22 ${secret_name}-2 &> /dev/null; then
      vault  kv get -mount secret22 ${secret_name}-2 | grep -qE '^foo\s+bar$'
      VAULT_SYNC_READY2="true"
    fi
    sleep 1
  done
  if [[ ! $VAULT_SYNC_READY1 || ! $VAULT_SYNC_READY2 ]]; then
    echo "vault-sync failed to sync on the event from the audit device"
    exit 1
  fi

  vault audit disable $audit_device_name

  kill $(<vault-sync.pid)
  rm vault-sync.pid
)}

# secret/src -> secret/dst
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync
full_sync_interval: 10
src:
  url: http://127.0.0.1:8200/
  prefix: src
dst:
  url: http://127.0.0.1:8200/
  prefix: dst
EOF

src_prefix="src/"
dst_prefix="dst/"

test_token secret
test_app_role secret

# secret1/src -> secret1/dst
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync
full_sync_interval: 10
src:
  url: http://127.0.0.1:8200/
  prefix: src
  backend: secret1
  version: 1
dst:
  url: http://127.0.0.1:8200/
  prefix: dst
  backend: secret1
  version: 1
EOF

src_prefix="src/"
dst_prefix="dst/"

test_token secret1
test_app_role secret1

# secret2/src -> secret2/dst
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync
full_sync_interval: 10
src:
  url: http://127.0.0.1:8200/
  prefix: src
  backend: secret2
dst:
  url: http://127.0.0.1:8200/
  prefix: dst
  backend: secret2
EOF

src_prefix="src/"
dst_prefix="dst/"

test_token secret2
test_app_role secret2

# secret1/src -> secret2/dst
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync
full_sync_interval: 10
src:
  url: http://127.0.0.1:8200/
  prefix: src
  backend: secret1
  version: 1
dst:
  url: http://127.0.0.1:8200/
  prefix: dst
  backend: secret2
EOF

src_prefix="src/"
dst_prefix="dst/"

test_token secret1 secret2
test_app_role secret1 secret2

# secret2/src -> secret1/dst
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync
full_sync_interval: 10
src:
  url: http://127.0.0.1:8200/
  prefix: src
  backend: secret2
dst:
  url: http://127.0.0.1:8200/
  prefix: dst
  backend: secret1
  version: 1
EOF

src_prefix="src/"
dst_prefix="dst/"

test_token secret2 secret1
test_app_role secret2 secret1

# secret1 -> secret2
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync
full_sync_interval: 10
src:
  url: http://127.0.0.1:8200/
  backend: secret1
  version: 1
dst:
  url: http://127.0.0.1:8200/
  backend: secret2
EOF

src_prefix=""
dst_prefix=""

test_token secret1 secret2
test_app_role secret1 secret2

# secret2 -> secret1
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync
full_sync_interval: 10
src:
  url: http://127.0.0.1:8200/
  backend: secret2
dst:
  url: http://127.0.0.1:8200/
  backend: secret1
  version: 1
EOF

src_prefix=""
dst_prefix=""

test_token secret2 secret1
test_app_role secret2 secret1

# Enable audit device that always works
vault audit enable -path vault-audit file file_path=vault-audit.log

# secret/src -> secret/dst
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync-secret
bind: 0.0.0.0:8202
full_sync_interval: 60
src:
  url: http://127.0.0.1:8200/
  prefix: src
dst:
  url: http://127.0.0.1:8200/
  prefix: dst
EOF

src_prefix="src/"
dst_prefix="dst/"

test_token_with_audit_device secret

# secret1/src -> secret1/dst
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync-secret
full_sync_interval: 60
bind: 0.0.0.0:8202
src:
  url: http://127.0.0.1:8200/
  prefix: src
  backend: secret1
  version: 1
dst:
  url: http://127.0.0.1:8200/
  prefix: dst
  backend: secret1
  version: 1
EOF

src_prefix="src/"
dst_prefix="dst/"

test_token_with_audit_device secret1

# secret2/src -> secret2/dst
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync-secret
full_sync_interval: 60
bind: 0.0.0.0:8202
src:
  url: http://127.0.0.1:8200/
  prefix: src
  backend: secret2
dst:
  url: http://127.0.0.1:8200/
  prefix: dst
  backend: secret2
EOF

src_prefix="src/"
dst_prefix="dst/"

test_token_with_audit_device secret2

# secret1 -> secret2
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync-secret
full_sync_interval: 60
bind: 0.0.0.0:8202
src:
  url: http://127.0.0.1:8200/
  backend: secret1
  version: 1
dst:
  url: http://127.0.0.1:8200/
  backend: secret2
EOF

src_prefix=""
dst_prefix=""

test_token_with_audit_device secret1 secret2

# secret2 -> secret1
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync-secret
full_sync_interval: 60
bind: 0.0.0.0:8202
src:
  url: http://127.0.0.1:8200/
  backend: secret2
dst:
  url: http://127.0.0.1:8200/
  backend: secret1
  version: 1
EOF

src_prefix=""
dst_prefix=""

test_token_with_audit_device secret2 secret1

# secret11, secret12 -> secret21, secret22
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync-secret
full_sync_interval: 60
bind: 0.0.0.0:8202
src:
  url: http://127.0.0.1:8200/
  backends:
    - secret11
    - secret12
dst:
  url: http://127.0.0.1:8200/
  backends:
    - secret21
    - secret22
EOF

test_multiple_backends
