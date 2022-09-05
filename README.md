# vault-sync

A poor man's tool to replicate secrets from one Vault instance to another.

## How it works

When vault-sync starts, it does a full copy of the secrets from the source Vault instance to the destination Vault instance.
Periodically, vault-sync does a full reconciliation to make sure all the destination secrets are up to date.

At the same time, you can manually enable the [Socket Audit Device](https://www.vaultproject.io/docs/audit/socket) for the source Vault,
so Vault will be sending audit logs to vault-sync.
Using these audit logs, vault-sync keeps the secrets in the destination Vault up to date.
Note that vault-sync does not create or delete the audit devices by itself.

It is possible to use the same Vault instance as the source and the destination.
You can use this feature to replicate a "folder" of secrets to another "folder" on the same server.
You need to specify different prefixes (`src.prefix` and `dst.prefix`) in the configuration file to make sure the source and the destination do not overlap.

## Limitations

* Only two Vault auth methods are supported: [Token](https://www.vaultproject.io/docs/auth/token) and [AppRole](https://www.vaultproject.io/docs/auth/approle)
* Only secrets are replicated (specifically their latest versions)
* Only secrets from the default secrets mount path `secret` are supported for the source and destination Vaults (this is due the limitation of the Vault client library)
* Deleting secrets is not supported (also due to the limitation of the Vault client library, which does not support deleting secret's metadata)

## Configuration

Use the [example](vault-sync.example.yaml) to create your own configuration file.
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

A token or AppRole for the source Vault should have a policy that allows listing and reading secrets:

```shell
cat <<EOF | vault policy write vault-sync-src -
path "secret/data/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/*" {
  capabilities = ["read", "list"]
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

Enabling audit log:

if you want to use the Vault audit device for vault-sync, then you need to create an audit device that always works.
If you have only one audit device enabled, and it is not working (for example, vault-sync has terminated), then Vault will be unresponsive.
Vault will not complete any requests until the audit device can write.
If you have more than one audit device, then Vault will complete the request as long as one audit device persists the log.
The simples way to create an audit device that always works:

```shell
vault audit enable -path stdout file file_path=stdout
```

Then, when vault-sync is running, create the audit device that will be sending audit logs to vault-sync:

```shell
vault audit enable -path vault-sync socket socket_type=tcp address=vault-sync:8202
```

The device name is `vault-sync`, use the same value as specified for `id` in the configuration file.
For `address`, specify the external endpoint for vault-sync.
It must be accessible from the Source Vault using this endpoint.

### Destination Vault

A token or AppRole for the source Vault should have a policy that allows operations on secrets:

```shell
cat <<EOF | vault policy write vault-sync-dst -
path "secret/data/*" {
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

```shell
vault-sync --config vault-sync.yaml
```

Command line options:

* `--dry-run` vault-sync shows all the changes it is going to make to the destination Vault, but does not do any actual changes.
* `--once` runs the full sync once, then exits.

## Installation

### From source code

```shell
cargo build --release
```

### Docker

Assuming your configuration file `vault-sync.yaml` is in the current directory: 

```shell
docker run -it -v $PWD:/vault-sync pbchekin/vault-sync:0.7.0 \
  vault-sync --config /vault-sync/vault-sync.yaml
```

### Helm chart

```shell
git clone https://github.com/pbchekin/vault-sync.git
cd install/helm/vault-sync/
kubectl create ns vault-sync
kubens vault-sync
# create myvalues.yaml, using values.yaml as the example
helm install vault-sync -f myvalues.yaml .
```
