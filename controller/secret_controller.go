// VSSO - Vault Secret Sync Operator
//
// Syncs selected keys from HashiCorp Vault (KV v2) into Kubernetes Secrets.
//
// HOW IT WORKS
// ------------
//  1. VSSO only reconcile Secrets that have the annotation `vault.hashicorp.com/path`.
//  2. Keys to fetch are determined by EITHER:
//     a) JSON mapping in annotation `vault.hashicorp.com/keys`
//     Example: {"username":"db_user","password":"db_pass"}
//     Meaning: Secret.data["username"] <- Vault.data["db_user"], etc.
//     b) Placeholders inside existing Secret data values, e.g.:
//     Secret.data["username"] = "<db_user>"  → maps to Vault.data["db_user"]
//     If both are present, JSON (a) wins for overlapping Secret keys.
//  3. VSSO authenticates to Vault using the Kubernetes auth method (short-lived SA token)
//     by using token of given NS SA (it "impersonating" it)
//  4. VSSO reads the Vault path and update only the discovered keys in the Secret.
//  5. VSSO annotates the Secret with the last synced timestamp, Vault version, and a hash of
//     applied values, then requeue after a configurable refresh period.

package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
	vaultk8s "github.com/hashicorp/vault/api/auth/kubernetes"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	crlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// ---- Annotations (inputs & bookkeeping) ----
const (
	// Inputs
	AnnoPath     = "vault.hashicorp.com/path"            // required: Vault KV path (relative to mount), e.g. "app/foo"
	AnnoMount    = "vault.hashicorp.com/mount"           // optional: KV mount name; default: namespace
	AnnoSA       = "vault.hashicorp.com/service-account" // optional: SA name for TokenRequest; default: "default"
	AnnoAudience = "vault.hashicorp.com/audience"        // optional: SA token audience; default: VAULT_DEFAULT_AUDIENCE
	AnnoRefresh  = "vault.hashicorp.com/refresh-time"    // optional: reconcile interval; default: DEFAULT_REFRESH_SECONDS

	// Operator-written annotations
	AnnoKeys        = "vault.hashicorp.com/keys" // optional: **JSON** mapping only (no key=value)
	AnnoLastSynced  = "vault.hashicorp.com/last-synced"
	AnnoLastVersion = "vault.hashicorp.com/kv-version"
	AnnoLastHash    = "vault.hashicorp.com/last-hash"
)

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create

// Placeholder pattern: a Secret value exactly equal to "<vaultKeyName>"
var placeholderRe = regexp.MustCompile(`^<([A-Za-z0-9_.-]+)>$`)

// SecretReconciler carries all dependencies and default behavior.
type SecretReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	RestConfig *rest.Config
	Recorder   record.EventRecorder

	// Vault config (from main.go / env)
	VaultAddr          string
	VaultK8sMount      string // e.g. "kubernetes"
	DefaultAudience    string
	DefaultSA          string
	CACertPath         string
	InsecureSkipVerify bool

	// KVGet is an optional test hook that overrides the Vault KVv2 Get call.
	// If nil, the reconciler uses the real client: vaultClient.KVv2(mount).Get(ctx, path).
	// Signature matches (*api.KVv2).Get to avoid downstream changes.
	// = IT IS USED FOR TESTING PURPOSES ONLY
	TestMockVaultGetFunc func(ctx context.Context, mount, path string) (*vaultapi.KVSecret, error)
}

// Reconcile only Secrets that declare AnnoPath.
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	onlyWithPath := predicate.NewPredicateFuncs(func(o client.Object) bool {
		_, ok := o.GetAnnotations()[AnnoPath]
		return ok
	})
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}, builder.WithPredicates(onlyWithPath)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 4}).
		Complete(r)
}

// -------------------------------
// RECONCILE entrypoint
// -------------------------------
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	startTime := time.Now()
	log := crlog.FromContext(ctx).WithValues("secret", req.NamespacedName.String())
	log.Info("RECONCILIATION Begin")

	// -------------------------------
	// 1) Fetch current Secret
	// -------------------------------
	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		if errors.IsNotFound(err) {
			log.Info("secret not found (deleted)")
			return requeueOrNot(0, nil, log, startTime)
		}
		return requeueOrNot(0, nil, log, startTime)
	}
	if secret.DeletionTimestamp != nil {
		log.Info("secret is deleting; skip")
		return requeueOrNot(0, nil, log, startTime)
	}
	annotations := secret.GetAnnotations()
	if annotations == nil {
		log.Info("no annotations; skip")
		return requeueOrNot(0, nil, log, startTime)
	}

	// -------------------------------
	// 2) Build config (annotations + defaults)
	// -------------------------------
	cfg, err := r.readConfig(&secret, annotations)
	if err != nil {
		log.Error(err, "invalid configuration")
		return requeueOrNot(cfg.Refresh, nil, log, startTime)
	}
	log.Info("config",
		"mount", cfg.Mount, "path", cfg.Path, "role", cfg.Role,
		"audience", cfg.Audience, "refresh", cfg.Refresh, "sa", cfg.SA,
	)

	// -------------------------------
	// 3) Determine which keys to fetch
	// -------------------------------
	keysToFetch, wantKeysJSON, needKeysAnnoUpdate, needRefreshAnno, discoverErr :=
		discoverKeys(&secret, annotations)
	if discoverErr != nil {
		// Invalid JSON in AnnoKeys should be obvious to users via event + error
		r.eventf(&secret, corev1.EventTypeWarning, "BadKeysAnnotation", "Invalid JSON in %s: %v", AnnoKeys, discoverErr)
		log.Error(discoverErr, "invalid JSON in AnnoKeys")
		return requeueOrNot(cfg.Refresh, err, log, startTime)
	}

	if len(keysToFetch) == 0 {
		log.Info("no keys via JSON or placeholders", "after", cfg.Refresh)
		return requeueOrNot(cfg.Refresh, nil, log, startTime)
	}
	log.Info("keys to sync", "keys", keysToFetch)

	// -------------------------------
	// 4) Get SA token and authenticate to Vault
	// -------------------------------

	vaultClient, err := r.newVaultClient()
	if err != nil {
		r.eventf(&secret, corev1.EventTypeWarning, "VaultClientInitFailed", "Failed to init Vault client: %v", err)
		return requeueOrNot(cfg.Refresh, nil, log, startTime)
	}

	// do not perform this during test
	if r.TestMockVaultGetFunc == nil {
		jwt, err := r.requestSAToken(ctx, req.Namespace, cfg.SA, cfg.Audience, 660) // 11 minutes

		if err != nil {
			r.eventf(&secret, corev1.EventTypeWarning, "TokenRequestFailed", "Failed to request SA token: %v", err)
			return requeueOrNot(cfg.Refresh, nil, log, startTime)
		}
		if err := r.vaultLoginWithK8S(ctx, vaultClient, jwt, cfg.Role); err != nil {
			r.eventf(&secret, corev1.EventTypeWarning, "VaultLoginFailed", "Vault login failed for role %q: %v", cfg.Role, err)
			return requeueOrNot(cfg.Refresh, nil, log, startTime)
		}
	}

	// -------------------------------
	// 5) Read Vault KV and apply to Secret data
	// -------------------------------
	ctxVault, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var vaultDocument *vaultapi.KVSecret
	if r.TestMockVaultGetFunc != nil {
		// Test override: use injected function instead of real network call
		vaultDocument, err = r.TestMockVaultGetFunc(ctxVault, cfg.Mount, cfg.Path)
	} else {
		// default production vault
		kv := vaultClient.KVv2(cfg.Mount)
		vaultDocument, err = kv.Get(ctxVault, cfg.Path)

	}
	if err != nil {
		reason := "KV get failed"
		err = fmt.Errorf("%s at %s/%s: %v", reason, cfg.Mount, cfg.Path, err)
		r.eventf(&secret, corev1.EventTypeWarning, "VaultGetFailed", "%s at at %s/%s: %v", reason, cfg.Mount, cfg.Path, err)
		return requeueOrNot(cfg.Refresh, err, log, startTime)
	}
	if vaultDocument == nil {
		reason := "nil response from Vault KV get"
		err = fmt.Errorf("%s at %s/%s: %v", reason, cfg.Mount, cfg.Path, err)
		r.eventf(&secret, corev1.EventTypeWarning, "VaultGetFailed", "%s at at %s/%s: %v", reason, cfg.Mount, cfg.Path, err)
		return requeueOrNot(cfg.Refresh, err, log, startTime)
	}

	newData, applied := buildPatchedData(&secret, vaultDocument.Data, keysToFetch)
	newHash := hashApplied(applied)
	oldHash := annotations[AnnoLastHash]

	var currVer, prevVer string
	if vaultDocument.VersionMetadata != nil {
		currVer = fmt.Sprint(vaultDocument.VersionMetadata.Version)
	}
	prevVer = annotations[AnnoLastVersion]

	// -------------------------------
	// 6) If nothing changed and no annotation normalization needed, just requeue
	// -------------------------------
	if prevVer == currVer && hashEqual(oldHash, applied) && !needKeysAnnoUpdate && !needRefreshAnno {
		log.Info("no changes detected")
		return requeueOrNot(cfg.Refresh, err, log, startTime)
	}

	// -------------------------------
	// 7) Patch Secret data + bookkeeping annotations
	// -------------------------------
	if errPatch := r.patchSecret(ctx, &secret, newData, newHash, vaultDocument, wantKeysJSON, needKeysAnnoUpdate); errPatch != nil {
		r.eventf(&secret, corev1.EventTypeWarning, "PatchFailed", "Failed to patch Secret: %v", errPatch)
		return requeueOrNot(cfg.Refresh, errPatch, log, startTime)
	}

	log.Info("secret synced from Vault",
		"name", req.NamespacedName,
		"mount", cfg.Mount,
		"path", cfg.Path,
		"keysUpdated", len(applied),
	)
	r.eventf(&secret, corev1.EventTypeNormal, "Synced", "Synced from Vault %s/%s (updated %d keys)", cfg.Mount, cfg.Path, len(applied))

	// -------------------------------
	// 8) Requeue after refresh duration
	// -------------------------------
	return requeueOrNot(cfg.Refresh, nil, log, startTime)
}

// -------------------------------
// Config & key discovery helpers
// -------------------------------

// config holds all effective inputs used during one reconciliation.
type config struct {
	Path     string // Vault path (relative to mount)
	Mount    string // KV mount (default: namespace)
	Role     string // Vault auth role (default: namespace)
	Audience string // SA token audience
	SA       string // service account name for TokenRequest
	Refresh  time.Duration
}

// readConfig reads annotations and defaults to produce a usable config and the refresh duration.
func (r *SecretReconciler) readConfig(sec *corev1.Secret, anns map[string]string) (config, error) {
	c := config{
		Path:     strings.TrimSpace(anns[AnnoPath]),
		Mount:    strings.TrimSpace(anns[AnnoMount]),
		Role:     sec.GetNamespace(), // default: namespace = Vault role
		Audience: strings.TrimSpace(anns[AnnoAudience]),
		SA:       strings.TrimSpace(anns[AnnoSA]),
	}
	if c.Path == "" {
		return c, fmt.Errorf("missing required annotation %q", AnnoPath)
	}
	if c.Mount == "" {
		c.Mount = sec.GetNamespace()
	}
	if c.Audience == "" {
		c.Audience = r.DefaultAudience
	}
	if c.SA == "" {
		c.SA = r.DefaultSA
	}
	var err error
	if anns[AnnoRefresh] != "" {
		c.Refresh, err = time.ParseDuration(anns[AnnoRefresh])
		if err != nil {
			fmt.Printf("error parsing %q: %v\n", anns[AnnoRefresh], err)
		} else {
			// if refresh is less then minute, set it to one minute to avoid too many reconciliation
			if c.Refresh < 60*time.Second {
				c.Refresh = 60 * time.Second
			}
		}
	} else {
		c.Refresh = 0
	}
	return c, err
}

// discoverKeys builds the final "secretKey -> vaultKey" map this sync will apply.
// - JSON in AnnoKeys is **required to be valid JSON** if present.
// - Placeholders are merged in for any Secret keys not already present in AnnoKeys.
// - Returns a canonical JSON string (wantJSON) for normalizing AnnoKeys.
func discoverKeys(
	sec *corev1.Secret,
	anns map[string]string,
) (
	keys map[string]string,
	wantJSON string,
	needKeysAnno bool,
	needRefreshAnno bool,
	err error,
) {
	keys = map[string]string{}

	// 1) Parse JSON mapping from annotation (if present). JSON only.
	if raw := strings.TrimSpace(anns[AnnoKeys]); raw != "" {
		if err = json.Unmarshal([]byte(raw), &keys); err != nil {
			return nil, "", false, false, fmt.Errorf("invalid JSON: %w", err)
		}
		// Ensure non-nil map even if "{}" provided.
		if keys == nil {
			keys = map[string]string{}
		}
	}

	// 2) Scan Secret data for placeholders and merge any missing mappings.
	for secretKey, val := range sec.Data {
		if m := placeholderRe.FindStringSubmatch(string(val)); m != nil {
			vaultKey := m[1]
			// Only add if JSON didn't already supply this secretKey.
			if _, exists := keys[secretKey]; !exists {
				keys[secretKey] = vaultKey
			}
		}
	}

	// 3) Decide whether to normalize AnnoKeys and refresh-seconds in the Secret.
	wantJSON = stableKeysJSON(keys)
	haveJSON := strings.TrimSpace(anns[AnnoKeys])
	needKeysAnno = haveJSON == "" || haveJSON != wantJSON
	return
}

// -------------------------------
// Vault + data application
// -------------------------------

// newVaultClient creates a Vault client honoring TLS env.
func (r *SecretReconciler) newVaultClient() (*vaultapi.Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = r.VaultAddr
	if r.CACertPath != "" {
		_ = cfg.ConfigureTLS(&vaultapi.TLSConfig{CACert: r.CACertPath, Insecure: r.InsecureSkipVerify})
	} else if r.InsecureSkipVerify {
		_ = cfg.ConfigureTLS(&vaultapi.TLSConfig{Insecure: true})
	}
	return vaultapi.NewClient(cfg)
}

// vaultLoginWithK8S exchanges a Kubernetes JWT for a Vault token via the K8s auth method.
func (r *SecretReconciler) vaultLoginWithK8S(ctx context.Context, cli *vaultapi.Client, jwt, role string) error {
	log := crlog.FromContext(ctx).WithValues("role", role, "k8sAuthMount", r.VaultK8sMount)
	auth, err := vaultk8s.NewKubernetesAuth(role,
		vaultk8s.WithServiceAccountToken(jwt),
		vaultk8s.WithMountPath(r.VaultK8sMount),
	)
	if err != nil {
		log.Error(err, "creating Kubernetes auth method failed")
		return err
	}
	sec, err := cli.Auth().Login(ctx, auth)
	if err != nil {
		log.Error(err, "Vault login request failed")
		return err
	}
	if sec == nil || sec.Auth == nil || sec.Auth.ClientToken == "" {
		return fmt.Errorf("Vault login returned empty token")
	}
	return nil
}

// requestSAToken mints a short-lived JWT via the TokenRequest API.
func (r *SecretReconciler) requestSAToken(ctx context.Context, namespace, sa, audience string, ttlSeconds int64) (string, error) {
	log := crlog.FromContext(ctx).WithValues("sa", sa, "ns", namespace, "audience", audience, "ttlSeconds", ttlSeconds)
	cs, err := kubernetes.NewForConfig(r.RestConfig)
	if err != nil {
		log.Error(err, "creating clientset failed")
		return "", err
	}
	tr := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: &ttlSeconds,
		},
	}
	tok, err := cs.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, sa, tr, metav1.CreateOptions{})
	if err != nil {
		log.Error(err, "CreateToken failed")
		return "", err
	}
	return tok.Status.Token, nil
}

// buildPatchedData applies Vault values to a copy of Secret.data for the discovered keys.
func buildPatchedData(
	sec *corev1.Secret,
	vdata map[string]interface{},
	keysToFetch map[string]string,
) (newData map[string][]byte, applied map[string]string) {
	// Start with a copy of existing Secret.data to avoid destructive updates.
	newData = make(map[string][]byte, len(sec.Data))
	for k, v := range sec.Data {
		newData[k] = v
	}
	applied = map[string]string{}

	// Helper to turn arbitrary JSON value into bytes and record its digest.
	apply := func(secretKey string, raw interface{}) {
		bs, _ := json.Marshal(raw) // tolerant: objects/arrays remain JSON
		// If the JSON is a string, unwrap to raw bytes for nicer UX.
		var s string
		if err := json.Unmarshal(bs, &s); err == nil {
			newData[secretKey] = []byte(s)
		} else {
			newData[secretKey] = bs
		}
		applied[secretKey] = digest(newData[secretKey])
	}

	// For each secretKey -> vaultKey mapping, copy from Vault if present.
	for secretKey, vaultKey := range keysToFetch {
		if raw, ok := vdata[vaultKey]; ok {
			apply(secretKey, raw)
		}
	}
	return newData, applied
}

// -------------------------------
// Patch + events + hashing
// -------------------------------

// patchSecret writes back data + annotations in one MergeFrom patch.
func (r *SecretReconciler) patchSecret(
	ctx context.Context,
	sec *corev1.Secret,
	newData map[string][]byte,
	newHash string,
	vaultDocument *vaultapi.KVSecret,
	wantKeysJSON string,
	needKeysAnno bool,
) error {
	patch := client.MergeFrom(sec.DeepCopy())
	sec.Data = newData
	if sec.Annotations == nil {
		sec.Annotations = map[string]string{}
	}
	sec.Annotations[AnnoLastSynced] = time.Now().UTC().Format(time.RFC3339)
	if vaultDocument != nil && vaultDocument.VersionMetadata != nil {
		sec.Annotations[AnnoLastVersion] = fmt.Sprint(vaultDocument.VersionMetadata.Version)
	}
	sec.Annotations[AnnoLastHash] = newHash
	if needKeysAnno {
		sec.Annotations[AnnoKeys] = wantKeysJSON // normalize to canonical JSON
	}
	return r.Patch(ctx, sec, patch)
}

// eventf emits a Kubernetes Event (if Recorder configured).
func (r *SecretReconciler) eventf(obj runtime.Object, etype, reason, msgFmt string, args ...interface{}) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(obj, etype, reason, msgFmt, args...)
}

// ---- Hashing & tiny utils ----
// this is helper fuction, once the secret does not have refresh annotation, then
// refresh is zero and the result should not requeue at all (otherwise it would
// requeue immediately creating a loop)
func requeueOrNot(refresh time.Duration, err error, log logr.Logger, start time.Time) (ctrl.Result, error) {
	if refresh > 0 {
		log.Info("RECONCILIATION End; requeued", "refresh", refresh, "elapsed", time.Since(start))
		return ctrl.Result{RequeueAfter: refresh}, err
	}
	log.Info("RECONCILIATION End; NOT requeued", "elapsed", time.Since(start))
	return ctrl.Result{}, err
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hashApplied(m map[string]string) string {
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hashEqual(prev string, m map[string]string) bool {
	return prev != "" && prev == hashApplied(m)
}

// stableKeysJSON produces canonical JSON (sorted keys) for neat diffs & idempotence.
// Example: map[string]string{"b":"B","a":"A"} → {"a":"A","b":"B"}
func stableKeysJSON(m map[string]string) string {
	type kv struct{ K, V string }
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].K < items[j].K })

	var b bytes.Buffer
	b.WriteString("{")
	for i, p := range items {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q:%q", p.K, p.V)
	}
	b.WriteString("}")
	return b.String()
}
