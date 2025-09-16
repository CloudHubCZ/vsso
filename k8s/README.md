# Test init
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
vault kv put sandbox-sit/gaas dbpass='S3cr3t-P@ss3'
vault kv get sandbox-sit/gaas

# RBAC
kubectl create clusterrolebinding vault-auth-delegator \
--clusterrole=system:auth-delegator \
--serviceaccount infra-vault:vault

# Create K8S auth
vault auth enable -path=aks kubernetes

# Build API server URL from pod env
K8S_HOST="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"



vault audit enable file file_path=/vault/logs/audit.log

vault write auth/aks/config \
kubernetes_host="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}" \
kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
issuer="https://westeurope.oic.prod-aks.azure.com/d831639f-a912-4e54-89a1-6e82b71411e2/abfef6d8-63b7-48f3-860a-7f72837a6ab5/" \
disable_iss_validation=false \
disable_local_ca_jwt=true

vault policy write sandbox-sit-policy - <<'EOF'
# Allow reads of KV v2 data and metadata under the sandbox-sit mount
path "sandbox-sit/data/*" {
capabilities = ["read"]
}
path "sandbox-sit/metadata/*" {
capabilities = ["read"]
}
EOF

vault write auth/aks/role/sandbox-sit \
bound_service_account_names="*" \
bound_service_account_namespaces="sandbox-sit" \
audience="vault" \
token_policies="sandbox-sit-policy" \
token_ttl="10m" token_max_ttl="1h"


# Test generate SA
kubectl -n sandbox-sit create token default --audience vault --duration 2m

curl -s -X POST http://127.0.0.1:8001/apis/authentication.k8s.io/v1/tokenreviews \
-H 'Content-Type: application/json' \
-d '{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"'"eyJhbGciOiJSUzI1NiIsImtpZCI6Im0tVHQ4SDZIc2R1NnpYbXZGYXRlQk16VzFCN3RYX2JYRnIzOWVnb01IaTgifQ.eyJhdWQiOlsidmF
1bHQiXSwiZXhwIjoxNzU3NDQ0NDA0LCJpYXQiOjE3NTc0NDM3NDQsImlzcyI6Imh0dHBzOi8vd2VzdGV1cm9wZS5vaWMucHJvZC1ha3MuYXp1cmUuY29tL2Q4MzE2MzlmLWE5MTItNGU1NC04OWExLTZlODJiNzE0
MTFlMi9hYmZlZjZkOC02M2I3LTQ4ZjMtODYwYS03ZjcyODM3YTZhYjUvIiwianRpIjoiNTNkZDk5NTUtMGUyZS00ODA0LTllYjgtY2U1OWM4MmU3NzhhIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJzY
W5kYm94LXNpdCIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJkZWZhdWx0IiwidWlkIjoiOTBhOWFiMjUtMThhYi00MzBiLWEzNWQtOTg1MzBmMmY5OTlkIn19LCJuYmYiOjE3NTc0NDM3NDQsInN1YiI6InN5c3
RlbTpzZXJ2aWNlYWNjb3VudDpzYW5kYm94LXNpdDpkZWZhdWx0In0.ll8hyAVutJR6bR1XS-EJjiDbXOA5S5xyhqxALA4rk3zAwTLytwD47-1bQvMracWvoIap_yvK9Gln-bTm5CZ9g6vZGLZB5k64fgcMm-D8WPH
LTX3G3j6zNTSNne3EspbhKEY9iOyGeybPtrM1C4ZtquqgwQlhEaeD3pVqD0C1Z6GXZOaXQwP6mPBjQipUs0tDrpZbltXAA0aT9vmrdVUyp0sM-ip4VeEi9N_8gKgv2Ky9GeS3M2xnNterj83nI0KptAt-uj0KDigN
w1hakyCDyMwf2jsszKcYNYEQ2Xh6-78FIrqzSL8QQJ4J27C3FLk026LRBxl7qoOLLDi1gxaF8aTxEGE642MnDGP1hU87RAUE0eLGhzVDdTRIOjX9CZzeGej7Onu3TiEvzeBKmp9_3SQjPKDx1UdzjHZK66SNPm2x9
vmrK2fTgSa_kQGELyOMFJZ5hMYfJdkmNicAcSVyfPrnQnEbxdO5SXAJZHVoe5asWTw5FpT5WxtwCdl9sj7Dgt0V1FqKpY5rXKOHYJp2PLS6qEdf-BV9IZRwHyXfJaP5qdgdmBoOXcNm8zEnSP1KTR-I0QcMmzCYst
tzOMdZaNlu3Yo3NgUzsjDr1CGpZzo13fNv6fpWG9Hof2bceMj3ynzvHiMC9ulyX1Co4yAQi7r5I5JPuJxWng25P69cx_k"'","audiences":["vault"]}}' \
| jq .