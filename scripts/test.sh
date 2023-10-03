#!/bin/bash

# Local test.
# Requires installed vault.
# TODO: use vault container instead of locally installed vault.

set -e

vault server -dev -dev-root-token-id=unsafe-root-token &> vault.log &
echo $! > vault.pid

function cleanup() {(
  set -e
  if [[ -f vault.pid ]]; then
    kill $(<vault.pid)  || true
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

# Enable secrets engine v1 at the path "secret1"
vault secrets enable -version=1 -path=secret1 kv

# Enable secrets engine v2 at the path "secret2"
vault secrets enable -version=2 -path=secret2 kv

vault secrets list

# Check all secret engines are enabled
vault secrets list | grep -qE '^secret/\s+kv'
vault secrets list | grep -qE '^secret1/\s+kv'
vault secrets list | grep -qE '^secret2/\s+kv'

# Create reader policy
cat <<EOF | vault policy write vault-sync-reader -
  # Default secret backend "secret"
  path "secret/data/*" {
    capabilities = ["read", "list"]
  }
  path "secret/metadata/*" {
    capabilities = ["read", "list"]
  }

  # Custom secret backend "secret1"
  path "secret1/data/*" {
    capabilities = ["read", "list"]
  }
  path "secret1/metadata/*" {
    capabilities = ["read", "list"]
  }

  # Custom secret backend "secret2"
  path "secret2/data/*" {
    capabilities = ["read", "list"]
  }
  path "secret2/metadata/*" {
    capabilities = ["read", "list"]
  }
EOF

# Create writer policy
cat <<EOF | vault policy write vault-sync-writer -
  # Default secret backend "secret"
  path "secret/data/*" {
    capabilities = ["create", "read", "update", "delete"]
  }

  # Custom secret backend "secret1"
  path "secret1/data/*" {
    capabilities = ["create", "read", "update", "delete"]
  }

  # Custom secret backend "secret2"
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

# Create config for the default backend "secret" and prefixes "src" and "dst".
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

function test_token() {(
  local backend=$1
  vault kv put -mount $backend src/test1-$backend foo=bar
  vault kv get -mount $backend src/test1-$backend

  source /tmp/vault-sync-token.env
  cargo run -- --config /tmp/vault-sync.yaml --once
  vault kv get -mount $backend dst/test1-$backend
)}

function test_app_role() {(
  local backend=$1
  vault kv put -mount $backend src/test2-$backend foo=bar
  vault kv get -mount $backend src/test2-$backend

  source /tmp/vault-sync-app-role.env
  cargo run -- --config /tmp/vault-sync.yaml --once
  vault kv get -mount $backend dst/test2-$backend
)}

test_token secret
test_app_role secret

# Create config for the custom backend "secret1" and prefixes "src" and "dst".
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync
full_sync_interval: 10
src:
  url: http://127.0.0.1:8200/
  prefix: src
  backend: secret1
dst:
  url: http://127.0.0.1:8200/
  prefix: dst
  backend: secret1
EOF

#FIXME: not implemented
#test_token secret1
#test_app_role secret1

# Create config for the custom backend "secret2" and prefixes "src" and "dst".
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

test_token secret2
test_app_role secret2

# Testing Vault audit device

function test_token_with_audit_device() {
  local backend=$1
  source /tmp/vault-sync-token.env

  vault kv put -mount $backend src/test3-$backend foo=bar

  cargo run -- --config /tmp/vault-sync.yaml &
  echo $! > vault-sync.pid

  echo Wating for vault-sync to start and make the initial sync ...
  VAULT_SYNC_READY=""
  for i in 1 2 3 4 5; do
    if vault kv get -mount $backend dst/test3-$backend 2> /dev/null; then
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
  vault audit enable -path vault-sync-$backend socket socket_type=tcp address=127.0.0.1:8202

  vault kv put -mount $backend src/test4-$backend foo=bar

  echo Wating for vault-sync to sync on event ...
  VAULT_SYNC_READY=""
  for i in 1 2 3 4 5; do
    if vault kv get -mount $backend dst/test4-$backend 2> /dev/null; then
      VAULT_SYNC_READY="true"
      break
    fi
    sleep 1
  done
  if [[ ! $VAULT_SYNC_READY ]]; then
    echo "vault-sync failed to sync on the event from the audit device"
    exit 1
  fi

  kill $(<vault-sync.pid)
  rm vault-sync.pid
}

# Enable audit device that always works
vault audit enable -path vault-audit file file_path=vault-audit.log

# Create config for the default backend "secret" and prefixes "src" and "dst".
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

test_token_with_audit_device secret

# Create config for the custom backend "secret2" and prefixes "src" and "dst".
cat <<EOF > /tmp/vault-sync.yaml
id: vault-sync-secret2
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

test_token_with_audit_device secret2
