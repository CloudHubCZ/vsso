// VSSO - Vault Secret Sync Operator
//
// Syncs selected keys from HashiCorp Vault (KV v2) into Kubernetes Secrets.
//
// HOW IT WORKS
// ------------
//  1. VSSO only reconcile Secrets that have the annotation `vault.ppfbanka.cz/path`.
//  2. Keys to fetch are determined by EITHER:
//     a) JSON mapping in annotation `vault.ppfbanka.cz/keys`
//     Example: {"username":"db_user","password":"db_pass"}
//     Meaning: Secret.data["username"] <- Vault.data["db_user"], etc.
//     b) Placeholders inside existing Secret data values, e.g.:
//     Secret.data["username"] = "<db_user>"  → maps to Vault.data["db_user"]
//     If both are present, JSON (a) wins for overlapping Secret keys.
//  3. VSSO authenticates to Vault using the Kubernetes auth method (short-lived SA token).
//  4. VSSO reads the Vault path and update only the discovered keys in the Secret.
//  5. VSSO annotates the Secret with last synced timestamp, Vault version, and a hash of
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
	"strconv"
	"strings"
	"time"

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
	AnnoPath        = "vault.ppfbanka.cz/path"            // required: Vault KV path (relative to mount), e.g. "app/foo"
	AnnoMount       = "vault.ppfbanka.cz/mount"           // optional: KV mount name; default: namespace
	AnnoSA          = "vault.ppfbanka.cz/service-account" // optional: SA name for TokenRequest; default: "default"
	AnnoAudience    = "vault.ppfbanka.cz/audience"        // optional: SA token audience; default: VAULT_DEFAULT_AUDIENCE
	AnnoRefreshSecs = "vault.ppfbanka.cz/refresh-seconds" // optional: reconcile interval; default: DEFAULT_REFRESH_SECONDS
	AnnoKeys        = "vault.ppfbanka.cz/keys"            // optional: **JSON** mapping only (no key=value)

	// Operator-written annotations
	AnnoLastSynced  = "vault.ppfbanka.cz/last-synced"
	AnnoLastVersion = "vault.ppfbanka.cz/kv-version"
	AnnoLastHash    = "vault.ppfbanka.cz/last-hash"
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
	VaultAddr             string
	VaultK8sMount         string // e.g. "kubernetes"
	DefaultAudience       string
	DefaultRefreshSeconds string
	CACertPath            string
	InsecureSkipVerify    bool
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
	start := time.Now()
	log := crlog.FromContext(ctx).WithValues("secret", req.NamespacedName.String())
	log.Info("reconcile: begin")
	defer func() { log.Info("reconcile: end", "elapsed", time.Since(start)) }()

	// -------------------------------
	// 1) Fetch current Secret
	// -------------------------------
	var sec corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &sec); err != nil {
		if errors.IsNotFound(err) {
			log.Info("secret not found (deleted)")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if sec.DeletionTimestamp != nil {
		log.Info("secret is deleting; skip")
		return ctrl.Result{}, nil
	}
	anns := sec.GetAnnotations()
	if anns == nil {
		log.Info("no annotations; skip")
		return ctrl.Result{}, nil
	}

	// -------------------------------
	// 2) Build config (annotations + defaults)
	// -------------------------------
	cfg, refreshDur, err := r.deriveConfig(&sec, anns)
	if err != nil {
		log.Error(err, "invalid configuration")
		return ctrl.Result{}, err
	}
	log.Info("config",
		"mount", cfg.Mount, "path", cfg.Path, "role", cfg.Role,
		"audience", cfg.Audience, "refresh", refreshDur, "sa", cfg.SA,
	)

	// -------------------------------
	// 3) Determine which keys to fetch
	// -------------------------------
	keysToFetch, addedByPlaceholders, wantKeysJSON, needKeysAnnoUpdate, needRefreshAnno, discoverErr :=
		discoverKeys(&sec, anns)
	if discoverErr != nil {
		// Invalid JSON in AnnoKeys should be obvious to users via event + error
		r.eventf(&sec, corev1.EventTypeWarning, "BadKeysAnnotation", "Invalid JSON in %s: %v", AnnoKeys, discoverErr)
		log.Error(discoverErr, "invalid JSON in AnnoKeys")
		return ctrl.Result{RequeueAfter: refreshDur}, discoverErr
	}
	if len(keysToFetch) == 0 {
		log.Info("no keys via JSON or placeholders; requeue", "after", refreshDur)
		return ctrl.Result{RequeueAfter: refreshDur}, nil
	}
	log.V(1).Info("keys to fetch", "keys", keysToFetch, "addedByPlaceholders", addedByPlaceholders)

	// -------------------------------
	// 4) Get SA token and authenticate to Vault
	// -------------------------------
	jwt, err := r.requestSAToken(ctx, req.Namespace, cfg.SA, cfg.Audience, 660) // 11 minutes

	if err != nil {
		r.eventf(&sec, corev1.EventTypeWarning, "TokenRequestFailed", "Failed to request SA token: %v", err)
		return ctrl.Result{RequeueAfter: refreshDur}, err
	}
	vClient, err := r.newVaultClient()
	if err != nil {
		r.eventf(&sec, corev1.EventTypeWarning, "VaultClientInitFailed", "Failed to init Vault client: %v", err)
		return ctrl.Result{RequeueAfter: refreshDur}, err
	}
	if err := r.vaultLoginWithK8S(ctx, vClient, jwt, cfg.Role); err != nil {
		r.eventf(&sec, corev1.EventTypeWarning, "VaultLoginFailed", "Vault login failed for role %q: %v", cfg.Role, err)

		return ctrl.Result{RequeueAfter: refreshDur}, err
	}

	// -------------------------------
	// 5) Read Vault KV and apply to Secret data
	// -------------------------------
	kv := vClient.KVv2(cfg.Mount)
	ctxVault, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	vdoc, err := kv.Get(ctxVault, cfg.Path)
	if err != nil {
		r.eventf(&sec, corev1.EventTypeWarning, "VaultGetFailed", "KV get failed at %s/%s: %v", cfg.Mount, cfg.Path, err)
		return ctrl.Result{RequeueAfter: refreshDur}, err
	}
	if vdoc == nil {
		return ctrl.Result{RequeueAfter: refreshDur}, fmt.Errorf("nil response from Vault KV get")
	}

	newData, applied := buildPatchedData(&sec, vdoc.Data, keysToFetch)
	newHash := hashApplied(applied)
	oldHash := anns[AnnoLastHash]

	var currVer, prevVer string
	if vdoc.VersionMetadata != nil {
		currVer = fmt.Sprint(vdoc.VersionMetadata.Version)
	}
	prevVer = anns[AnnoLastVersion]

	// -------------------------------
	// 6) If nothing changed and no annotation normalization needed, just requeue
	// -------------------------------
	if prevVer == currVer && hashEqual(oldHash, applied) && !needKeysAnnoUpdate && !needRefreshAnno {
		log.Info("no changes; requeue", "after", refreshDur)
		return ctrl.Result{RequeueAfter: refreshDur}, nil
	}

	// -------------------------------
	// 7) Patch Secret data + bookkeeping annotations
	// -------------------------------
	if err := r.patchSecret(ctx, &sec, newData, newHash, vdoc, wantKeysJSON, needKeysAnnoUpdate, needRefreshAnno, cfg.RefreshSecs); err != nil {
		r.eventf(&sec, corev1.EventTypeWarning, "PatchFailed", "Failed to patch Secret: %v", err)
		return ctrl.Result{RequeueAfter: refreshDur}, err
	}

	log.Info("secret synced from Vault",
		"name", req.NamespacedName,
		"mount", cfg.Mount,
		"path", cfg.Path,
		"keysUpdated", len(applied),
	)
	r.eventf(&sec, corev1.EventTypeNormal, "Synced", "Synced from Vault %s/%s (updated %d keys)", cfg.Mount, cfg.Path, len(applied))

	// -------------------------------
	// 8) Requeue after refresh duration
	// -------------------------------
	return ctrl.Result{RequeueAfter: refreshDur}, nil
}

// -------------------------------
// Config & key discovery helpers
// -------------------------------

// config holds all effective inputs used during one reconciliation.
type config struct {
	Path        string // Vault path (relative to mount)
	Mount       string // KV mount (default: namespace)
	Role        string // Vault auth role (default: namespace)
	Audience    string // SA token audience
	RefreshSecs string // string form we keep in annotations
	SA          string // service account name for TokenRequest
}

// deriveConfig reads annotations and defaults to produce a usable config and the refresh duration.
func (r *SecretReconciler) deriveConfig(sec *corev1.Secret, anns map[string]string) (config, time.Duration, error) {
	c := config{
		Path:     strings.TrimSpace(anns[AnnoPath]),
		Mount:    strings.TrimSpace(anns[AnnoMount]),
		Role:     sec.GetNamespace(), // default: namespace = Vault role
		Audience: strings.TrimSpace(anns[AnnoAudience]),
		SA:       strings.TrimSpace(anns[AnnoSA]),
	}
	if c.Path == "" {
		return c, 0, fmt.Errorf("missing required annotation %q", AnnoPath)
	}
	if c.Mount == "" {
		c.Mount = sec.GetNamespace()
	}
	if c.Audience == "" {
		c.Audience = r.DefaultAudience
	}
	refresh := anns[AnnoRefreshSecs]
	if refresh == "" {
		refresh = r.DefaultRefreshSeconds
	}
	c.RefreshSecs = refresh

	secs, err := strconv.ParseInt(refresh, 10, 64)
	if err != nil {
		secs, _ = strconv.ParseInt(r.DefaultRefreshSeconds, 10, 64)
	}
	if c.SA == "" {
		c.SA = "default"
	}
	return c, time.Duration(secs) * time.Second, nil
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
	addedByPlaceholders bool,
	wantJSON string,
	needKeysAnno bool,
	needRefreshAnno bool,
	err error,
) {
	keys = map[string]string{}

	// 1) Parse JSON mapping from annotation (if present). JSON only.
	if raw := strings.TrimSpace(anns[AnnoKeys]); raw != "" {
		if err = json.Unmarshal([]byte(raw), &keys); err != nil {
			return nil, false, "", false, false, fmt.Errorf("invalid JSON: %w", err)
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
				addedByPlaceholders = true
			}
		}
	}

	// 3) Decide whether to normalize AnnoKeys and refresh-seconds in the Secret.
	wantJSON = stableKeysJSON(keys)
	haveJSON := strings.TrimSpace(anns[AnnoKeys])
	needKeysAnno = haveJSON == "" || haveJSON != wantJSON
	needRefreshAnno = anns[AnnoRefreshSecs] == ""
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
	vdoc *vaultapi.KVSecret,
	wantKeysJSON string,
	needKeysAnno, needRefreshAnno bool,
	refreshSecs string,
) error {
	patch := client.MergeFrom(sec.DeepCopy())
	sec.Data = newData
	if sec.Annotations == nil {
		sec.Annotations = map[string]string{}
	}
	sec.Annotations[AnnoLastSynced] = time.Now().UTC().Format(time.RFC3339)
	if vdoc != nil && vdoc.VersionMetadata != nil {
		sec.Annotations[AnnoLastVersion] = fmt.Sprint(vdoc.VersionMetadata.Version)
	}
	sec.Annotations[AnnoLastHash] = newHash
	if needKeysAnno {
		sec.Annotations[AnnoKeys] = wantKeysJSON // normalize to canonical JSON
	}
	if needRefreshAnno {
		sec.Annotations[AnnoRefreshSecs] = refreshSecs
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
