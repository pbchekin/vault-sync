#!/bin/bash

# Local test for vault-sync. Requires installed docker, kind, kubectl.

set -e -o pipefail

: ${GITHUB_SHA:=$(git describe --always)}

function cleanup() {
    kind delete cluster || true
}

trap cleanup EXIT

# Create Kubernetes cluster
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.29.4
EOF

# Deploy Vault
kubectl create ns vault
helm repo add hashicorp https://helm.releases.hashicorp.com
helm upgrade --install vault hashicorp/vault --namespace=vault --set server.dev.enabled=true --set injector.enabled=false

# Wait for Vault readiness
kubectl --namespace=vault get service
for i in $(seq 1 30); do
    if kubectl --namespace=vault get pods 2>/dev/null | grep -q vault-0 &>/dev/null; then
        break
    fi
    sleep 1
done
kubectl --namespace=vault wait pod/vault-0 --for=condition=Ready --timeout=180s
kubectl --namespace=vault logs vault-0

# Create secret backends
kubectl --namespace=vault exec vault-0 -- vault secrets enable -version=2 -path=src kv
kubectl --namespace=vault exec vault-0 -- vault secrets enable -version=2 -path=dst kv
kubectl --namespace=vault exec vault-0 -- vault kv put -mount src test1 foo=bar

# Build Docker image
docker build -t pbchekin/vault-sync:$GITHUB_SHA -f docker/Dockerfile .

# Load Docker image to the cluster
kind load docker-image pbchekin/vault-sync:$GITHUB_SHA

# Deploy vault-sync
kubectl create namespace vault-sync
cd install/helm/vault-sync/
helm install --namespace=vault-sync vault-sync -f - . <<EOF
image:
    tag: $GITHUB_SHA
vaultSync:
    id: vault-sync
    full_sync_interval: 3600
    src:
        url: http://vault.vault.svc.cluster.local:8200
        backend: src
    dst:
        url: http://vault.vault.svc.cluster.local:8200
        backend: dst
# Secrets must be base64 encoded
secrets:
    VAULT_SYNC_SRC_TOKEN: cm9vdA==
    VAULT_SYNC_DST_TOKEN: cm9vdA==
EOF

# Wait for vault-sync readiness
for i in $(seq 1 30); do
    if kubectl --namespace=vault-sync get pods 2>/dev/null | grep -q vault-sync &>/dev/null; then
        break
    fi
    sleep 1
done
if ! kubectl --namespace=vault-sync wait pod -l app.kubernetes.io/instance=vault-sync --for=condition=Ready --timeout=180s; then
    kubectl get pods -A
    kubectl --namespace=vault-sync logs -l app.kubernetes.io/instance=vault-sync
    exit 1
fi

# Check sync result
sleep 5
kubectl --namespace=vault exec vault-0 -- vault kv get -mount dst test1

# Show vault-sync logs
kubectl --namespace=vault-sync logs -l app.kubernetes.io/instance=vault-sync

# Test external secret
kubectl delete namespace vault-sync
kubectl --namespace=vault exec vault-0 -- vault kv put -mount src test2 foo=bar
kubectl create namespace vault-sync
kubectl --namespace=vault-sync create secret generic vault-sync-secret \
    --from-literal=VAULT_SYNC_SRC_TOKEN=root \
    --from-literal=VAULT_SYNC_DST_TOKEN=root

helm install --namespace=vault-sync vault-sync -f - . <<EOF
image:
    tag: $GITHUB_SHA
vaultSync:
    id: vault-sync
    full_sync_interval: 3600
    src:
        url: http://vault.vault.svc.cluster.local:8200
        backend: src
    dst:
        url: http://vault.vault.svc.cluster.local:8200
        backend: dst
existingSecretName: vault-sync-secret
EOF

# Wait for vault-sync readiness
for i in $(seq 1 30); do
    if kubectl --namespace=vault-sync get pods | grep -q vault-sync &>/dev/null; then
        break
    fi
    sleep 1
done
if ! kubectl --namespace=vault-sync wait pod -l app.kubernetes.io/instance=vault-sync --for=condition=Ready --timeout=180s; then
    kubectl get pods -A
    kubectl --namespace=vault-sync logs -l app.kubernetes.io/instance=vault-sync
    exit 1
fi

# Check sync result
sleep 5
kubectl --namespace=vault exec vault-0 -- vault kv get -mount dst test2

# Show vault-sync logs
kubectl --namespace=vault-sync logs -l app.kubernetes.io/instance=vault-sync
