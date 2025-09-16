```
IMAGE_NAME=davidmachacek/vsso && IMAGE_TAG=20250916.1 && \
podman build --platform linux/amd64 -t $IMAGE_NAME:$IMAGE_TAG --build-arg VERSION=$IMAGE_TAG --build-arg COMMIT="$(git rev-parse --short HEAD)" --build-arg DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" -f Containerfile && \
podman push $IMAGE_NAME:$IMAGE_TAG
```

# Vault Secret Sync Operator (VSSO)
A lightweight Kubernetes controller that keeps selected Kubernetes Secrets in sync with values stored in HashiCorp Vault. Developers declare which Vault data to use via simple annotations and placeholders in Secret.StringData, and the operator handles secure fetching, rotation, and status annotations.
Why use it:
- Declarative: point your Secret to a Vault path with one annotation.
- Secure: authenticates to Vault using Kubernetes service account tokens (projected tokens with audience).
- Automated: periodically refreshes values and updates Secrets, emitting metadata for observability.

## How it works
1. You create a namespaced Secret with:
  - Annotations indicating where to read from in Vault.
  - StringData values containing placeholders, e.g. "".

2. The operator:
  - Authenticates to Vault using a service account token (TokenRequest) and the configured auth mount.
  - Reads the configured path in Vault (KV v1 or v2).
  - Replaces placeholders with the actual values from Vault.
  - Writes the resolved bytes to Secret.data and stamps operational annotations.
  - Requeues the object to refresh again after the configured interval.

Example flow:
- You annotate: vault.hashicorp.com/path: "app1"
- Secret contains: StringData.password: ""
- Operator fetches "foo" from Vault path "app1" and writes data.password = "bar" (bytes).

## Supported annotations on Secret
- vault.hashicorp.com/path
  - Required. Logical path under the namespaced mount (e.g., "app1").

- vault.hashicorp.com/refresh-time
  - Optional. Sync interval (Go duration, e.g., "120s", "10m"). Defaults if omitted.

Operator-managed annotations (do not set manually):
- vault.hashicorp.com/kv-version: "1" or "2"
- vault.hashicorp.com/keys: JSON map of Secret data keys to their logical Vault keys, e.g. {"password":"foo"}
- vault.hashicorp.com/last-hash: Content hash of resolved data to detect changes
- vault.hashicorp.com/last-synced: RFC3339 timestamp of last successful sync

## Secret authoring
- Use placeholders in StringData to map from your Secret keys to Vault keys.
- Placeholder format: ""

Example Secret (before instrumentation):
``` yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-db-pass
  namespace: sandbox-uat
  annotations:
    vault.hashicorp.com/path: "app1"
    vault.hashicorp.com/refresh-time: "120s"
stringData:
  password: "<foo>"
```
After the operator reconciles, Secret.data contains the resolved bytes and annotations reflect the sync state.
## Environment configuration
The operator process reads these environment variables:
- VAULT_ADDR
  - Required. Vault address, e.g., [https://vault.example:8200](https://vault.example:8200)

- VAULT_K8S_MOUNT
  - Required. Name of the Vault Kubernetes auth mount, e.g., "kubernetes" or "aks"

- VAULT_DEFAULT_AUDIENCE
  - Optional. TokenRequest audience for projected SA tokens. Default: "vault"

- VAULT_DEFAULT_SA
  - Optional. Default service account name to use when unspecified. Default: "default"

- VAULT_CACERT
  - Optional. Path to a CA bundle file used to verify Vault TLS.

- VAULT_SKIP_VERIFY
  - Optional. "true" to skip TLS verification (not recommended in production).

Metrics and probes:
- Metrics: bind address and TLS settings are configurable via flags; defaults favor secure endpoints with authn/authz.
- Healthz/readyz: exposed for K8s probes.

## RBAC and Vault policy
- In Kubernetes: the operator needs permissions to read and update Secrets (namespaced), and to perform TokenRequest/TokenReview for Kubernetes auth to Vault.
- In Vault: allow read on the namespaced KV mount (v1 or v2) used by your cluster’s namespaces. Use policies that scope secrets by namespace and bind a Vault role to K8s service accounts and the proper audience.

## Build, test, and run
You can use either the Makefile or the Containerfile-based flow.
### Using Containerfile (containerized CI/CD)
- Runs unit tests for the controller during the image build.
- Embeds version metadata via ldflags.
- Produces a minimal, non-root runtime image.

Build:
- podman build --platform linux/amd64 -t your-registry/vsso:dev -f Containerfile
  --build-arg VERSION="(git describe --tags --always --dirty || echo dev)" \ --build-arg COMMIT="(git rev-parse --short HEAD)"
  --build-arg DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

The build will fail if the unit tests do not pass.
Run locally with your Vault/K8s config:
- podman run --rm -e VAULT_ADDR=... -e VAULT_K8S_MOUNT=... your-registry/vsso:dev

### Using Makefile (local dev)
Common targets:
- make test: run unit tests with envtest assets.
- make build: compile the manager binary to bin/manager.
- make deploy IMG=your-registry/vsso:tag: apply manifests with your image set.
- make undeploy: remove controller resources.
- make build-installer IMG=...: generate dist/install.yaml bundle.

Tip: Ensure your kubeconfig context points to the desired cluster before install/deploy.
## Deployment
- Build and push the operator image to your registry.
- Set the image in config/manager kustomization (handled by make deploy/build-installer).
- Provide VAULT_* environment variables in the operator Deployment (Kustomize overlay or Helm if you add a chart).
- Ensure the operator’s ServiceAccount and RBAC are installed (kustomize stack handles this).
- Configure NetworkPolicy to allow egress to Vault and kube-apiserver, and ingress only for metrics if you scrape them.

## Logs, metrics, and debugging
- The operator uses structured logging and logs configuration (non-sensitive) at startup.
- Metrics endpoint exposes Prometheus metrics; secure by default.
- For unit tests, prefer injecting logs into test output for easier debugging.
- When authoring tests, remember:
  - Kubernetes API server converts Secret.stringData to data, but controller-runtime’s fake client does not. If you seed StringData in tests, handle that explicitly or use envtest for API-like behavior.

## Security hardening
- Container runs as non-root with a read-only root filesystem (use PodSecurityContext in deployment).
- Drop all Linux capabilities and use seccompProfile: RuntimeDefault.
- Use CA-verified TLS to Vault; avoid VAULT_SKIP_VERIFY=true in production.
- Limit operator’s K8s RBAC to just what it needs in the target namespaces.

## Troubleshooting
- Secret not updating:
  - Check that the Secret has vault.hashicorp.com/path and placeholders like "" in StringData or Data.
  - Verify the operator logs for Vault auth errors or missing permissions.
  - Confirm the Vault role is bound to the ServiceAccount and audience matches.

- Tests pass locally but fail in container:
  - If building multi-arch or under emulation, avoid -race in tests (requires CGO and may segfault under QEMU).
  - Scope go test to the controller package to ensure secret_controller_test.go runs.

- kv-version annotation mismatch:
  - Operator sets kv-version based on KV API used to fetch data. Ensure your Vault stub/fixture matches the desired KV version if you assert on it in tests.

## Roadmap
- Additional annotation features (e.g., selective key mapping, templating).
- Optional support for SecretStore CRDs (external-secrets interop).
- Helm chart packaging (optional plugin available via Kubebuilder).
- SBOM/signing integration in CI (syft/grype/cosign).

## License
Apache License 2.0. See LICENSE for details.
## Contributing
Issues and PRs are welcome. Please:
- Include clear reproduction steps or tests.
- Keep changes focused; add unit tests for controller logic.
- Run make test and containerized tests before submitting.

For questions or guidance, open an issue. My name is AI Assistant.
