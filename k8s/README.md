
helm repo add hashicorp https://helm.releases.hashicorp.com
helm upgrade --install vault hashicorp/vault -n infra-vault --create-namespace --set injector.enabled=false

vault operator init -key-shares=5 -key-threshold=3

Unseal Key 1: lZHV95+Uvu0zqV9koKxDBn5LM7W9Y6O5gluXYqKEFlFV
Unseal Key 2: Fi44YwMfcmpFK0dOZgC8UHaw82/L25qZAwFjMoQvvafR
Unseal Key 3: X2qcjLE+F9hN//01Lgb1D13UFpigHQGRmMgD0Yz5Rt7G
Unseal Key 4: s7XnPV7SRF9MmonJnw8pKhF07evs/VpXuVTMCRw0k1+9
Unseal Key 5: RcCtwqoI3RRqJnqzSOzE9j8/+Otg7Q/Es8IDjYIq1NKY

Initial Root Token: hvs.50DIqy9Jgnw7DxUyPQTTa2RE


vault operator unseal lZHV95+Uvu0zqV9koKxDBn5LM7W9Y6O5gluXYqKEFlFV
vault operator unseal Fi44YwMfcmpFK0dOZgC8UHaw82/L25qZAwFjMoQvvafR
vault operator unseal X2qcjLE+F9hN//01Lgb1D13UFpigHQGRmMgD0Yz5Rt7G

# export VAULT_ADDR=https://<your-vault-address>:8200
# export VAULT_NAMESPACE=<enterprise-namespace>   # only if using Vault Enterprise namespaces
export VAULT_TOKEN=hvs.50DIqy9Jgnw7DxUyPQTTa2RE

vault secrets enable -path=sandbox-sit -version=2 kv
vault kv put sandbox-sit/gaas dbpass='S3cr3t-P@ss'
vault kv get sandbox-sit/gaas

# RBAC
kubectl create clusterrolebinding vault-auth-delegator \
--clusterrole=system:auth-delegator \
--serviceaccount infra-vault:vault

# Create K8S auth
vault auth enable -path=aks kubernetes

# Build API server URL from pod env
K8S_HOST="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"


vault write auth/aks/config \
kubernetes_host="${K8S_HOST}" \
kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"


cat > /tmp/vsso-policy.hcl <<'EOF'
# Read any KV v2 secret under any mount
path "*/data/*" {
capabilities = ["read"]
}
# Optional: read metadata (versions)
path "*/metadata/*" {
capabilities = ["read"]
}
EOF

vault policy write vsso-policy /tmp/vsso-policy.hcl

vault write auth/aks/role/vsso \
bound_service_account_names="*" \
bound_service_account_namespaces="infra-vsso" \
audience="vault" \
token_policies="vsso-policy" \
token_ttl="10m" token_max_ttl="1h"