# vault-sync

A poor man's tool to replicate secrets from one Vault instance to another.

## How it works
When vault-sync starts, it does a full copy of the secrets from the source Vault instance to the destination Vault instance.
At the same time, it enables the [Socket Audit Device](https://www.vaultproject.io/docs/audit/socket) for the source Vault,
so Vault starts sending audit logs to vault-sync.
Using these audit logs, vault-sync keeps the secrets in the destination Vault up to date.
Periodically, vault-sync does a full reconciliation to make sure all the destination secrets are up to date.

It is possible to use the same Vault instance as the source and the destination.
You can use this feature to replicate a "folder" of secrets to another "folder" on the same server.
You need to specify different prefixes (`src.prefix` and `dst.prefix`) in the configuration file to make sure the source and the destination do not overlap.

## Limitations
* Only two Vault auth methods are supported: [Token](https://www.vaultproject.io/docs/auth/token) and [AppRole](https://www.vaultproject.io/docs/auth/approle)
* Only secrets from the default secrets mount path `secret` are supported for the source and destination Vaults (this is due the limitation of the Vault client library)
* Deleting secrets is not supported (also due to the limitation of the Vault client library, which does not support deleting secret's metadata)

## Configuration
Use [vault-sync.example.yaml] to create a configuration file.
Instead of specifying secrets in the configuration file, you can use environment variables:
* For Token auth method:
  * `VAULT_SYNC_SRC_TOKEN`
  * `VAULT_SYNC_DST_TOKEN`
* For AppRole auth method:
  * `VAULT_SYNC_SRC_ROLE_ID`
  * `VAULT_SYNC_SRC_SECRET_ID`
  * `VAULT_SYNC_DST_ROLE_ID`
  * `VAULT_SYNC_DST_SECRET_ID`

### Source Vault
A token or AppRole for the source Vault should have a policy that allows listing and reading secrets and creating and deleting audit devices:

```shell
cat <<EOF | vault policy write vault-sync-src -
path "secret/data*" {
  capabilities = ["read", "list"]
}
path "secret/metadata*" {
  capabilities = ["read", "list"]
}
path "sys/audit*" {
  capabilities = ["create", "read", "list", "update", "delete", "sudo"]
}
EOF
```

To create a token for vault-sync for the source Vault:

```shell
vault token create -policy=vault-sync-src
```

To enable AppRole auth method and create AppRole for vault-sync for the source Vault:

```shell
# Enable approle auth method
vault auth enable approle
# Create a new approle and assign the policy
vault write auth/approle/role/vault-sync-src token_policies=vault-sync-src
# Get role id
vault read auth/approle/role/vault-sync-src/role-id
# Get secret id
vault write -f auth/approle/role/vault-sync-src/secret-id
```

### Destination Vault
A token or AppRole for the source Vault should have a policy that allows operations on secrets:

```shell
cat <<EOF | vault policy write vault-sync-dst -
path "secret/data*" {
  capabilities = ["create", "read", "update", "delete"]
}
EOF
```

To create a token for vault-sync for the source Vault:

```shell
vault token create -policy=vault-sync-dst
```

To enable AppRole auth method and create AppRole for vault-sync for the source Vault:

```shell
# Enable approle auth method
vault auth enable approle
# Create a new approle and assign the policy
vault write auth/approle/role/vault-sync-dst token_policies=vault-sync-dst
# Get role id
vault read auth/approle/role/vault-sync-dst/role-id
# Get secret id
vault write -f auth/approle/role/vault-sync-dst/secret-id
```

## Running
Then run `vault-sync --config vault-sync.yaml`.
With the command line option `--dry-run` vault-sync shows all the changes it is going to make to the destination Vault, but does not do any actual changes.

## Installation

* From the source code: `cargo build --release`
* Docker image (TODO)
* Helm chart (TODO)
