// native Kubernetes Secrets and, based on vault.* annotations, replaces
// placeholder values with data fetched from HashiCorp Vault (KV v2).
//
// High-level flow for each Secret:
//  1. Detect placeholders like "<dbpass>".
//  2. Mint a short-lived projected token for the configured ServiceAccount
//     using the TokenRequest API (audience defaults to "vault").
//  3. Log into Vault via the Kubernetes auth method at the configured mount
//     path (e.g. "aks") and role (e.g. "vsso").
//  4. Read the KV v2 document at:  <mount>/data/<path>
//  5. Patch the Secret's data and mark it with sync annotations.
//  6. Requeue periodically (refresh) to detect upstream changes.
//
// Security & privacy notes:
//   - We never log secret values; logs only indicate which keys were updated.
//   - We emit Kubernetes Events on common failure points (token, login, KV get, patch).
//   - Reconcile returns an error on failure (no custom requeue), so controller-runtime
//     backs off exponentially; on success we requeue after the configured refresh.
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
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

// Annotations that drive the operator behavior.
const (
	// AnnoPath is the relative KV path inside the chosen mount (required).
	// Example: if mount defaults to the Secret namespace, and AnnoPath="gaas",
	// the operator will read from: <mount>/data/gaas
	AnnoPath = "vault.ppfbanka.cz/path"

	// AnnoMount allows overriding the Vault KV mount (defaults to Secret namespace).
	AnnoMount = "vault.ppfbanka.cz/mount"

	// AnnoRole overrides the Vault Kubernetes auth role (defaults to VAULT_DEFAULT_ROLE).
	AnnoRole = "vault.ppfbanka.cz/role"

	// AnnoSA overrides the ServiceAccount used for TokenRequest (defaults to "default").
	AnnoSA = "vault.ppfbanka.cz/service-account"

	// AnnoAudience overrides the TokenRequest audience (defaults to VAULT_DEFAULT_AUDIENCE).
	AnnoAudience = "vault.ppfbanka.cz/audience"

	// AnnoRefreshSecs controls the periodic success requeue interval (in seconds).
	AnnoRefreshSecs = "vault.ppfbanka.cz/refresh-seconds"

	// AnnoForceSync if set to "true" also copies Vault keys that match existing
	// Secret keys even when they are not in placeholder form.
	AnnoForceSync = "vault.ppfbanka.cz/force-sync"

	// Read-only annotations written by the operator to aid troubleshooting.
	AnnoLastSynced  = "vault.ppfbanka.cz/last-synced" // RFC3339 UTC timestamp
	AnnoLastVersion = "vault.ppfbanka.cz/kv-version"  // KV version number
	AnnoLastHash    = "vault.ppfbanka.cz/last-hash"   // hash of applied keys
)

// Placeholders look like "<dbpass>"; the captured token is the Vault key name.
var placeholderRe = regexp.MustCompile(`^<([A-Za-z0-9_.-]+)>$`)

// SecretReconciler reconciles core/v1 Secrets that carry our annotations.
// Fields are injected from main.go during manager setup.
type SecretReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	RestConfig *rest.Config
	Recorder   record.EventRecorder // emits Kubernetes Events on noteworthy actions
	// Vault connection & auth configuration (derived from env in main.go).
	VaultAddr string
	//VaultNamespace     string // Vault Enterprise namespace
	VaultK8sMount      string // e.g. "kubernetes"
	DefaultRole        string
	DefaultAudience    string
	DefaultRefresh     time.Duration
	CACertPath         string
	InsecureSkipVerify bool
}

//Kubebuilder RBAC markers. They’re just Go comments that controller-gen parses to generate Kubernetes RBAC YAML (ClusterRoles) for operator.
// RBAC requirements for watching/patching Secrets and for TokenRequest/TokenReview.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create

// SetupWithManager wires the controller to reconcile only Secrets that have
// the required path annotation.
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// predicate definition
	pred := predicate.NewPredicateFuncs(func(o client.Object) bool {
		_, ok := o.GetAnnotations()[AnnoPath]
		return ok
	})
	// care only for secrets with given predicate (annotation with Vault path)
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}, builder.WithPredicates(pred)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 4}).
		Complete(r)
}

// Reconcile implements the fetch→auth→read→patch loop described above.
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	log := crlog.FromContext(ctx).WithValues("secret", req.NamespacedName.String())

	log.Info("operation=reconcileBegin")
	defer func() { log.Info("operation=reconcileEnd, result=INSTRUMENTED", "duration", time.Since(start)) }()

	// --- Fetch Secret ---
	var sec corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &sec); err != nil {
		if errors.IsNotFound(err) {
			log.Info("operation=reconcileConfig, message=secret not found; likely deleted, nothing to do")
			return ctrl.Result{}, nil
		}
		log.Error(err, "operation=reconcileConfig, message=failed to GET Secret from API")
		return ctrl.Result{}, err
	}
	if sec.DeletionTimestamp != nil {
		log.Info("operation=reconcileConfig, message=secret has DeletionTimestamp, result=SKIPPING")
		return ctrl.Result{}, nil
	}

	// --- Parse annotations into an effective config ---
	anns := sec.GetAnnotations()
	if anns == nil {
		log.V(1).Info("operation=reconcileConfig, message=no annotations present, result=SKIPPING")
		return ctrl.Result{}, nil
	}
	path := anns[AnnoPath]
	if path == "" {
		log.V(1).Info("operation=reconcileConfig, message=required annotation missing, result=SKIPPING", "annotation", AnnoPath)
		return ctrl.Result{}, nil
	}
	mount := anns[AnnoMount]
	if mount == "" { // default mount is the Secret's namespace
		mount = sec.GetNamespace()
		log.V(1).Info("operation=reconcileConfig, message=mount default fallback", "mount", mount)
	}
	role := anns[AnnoRole]
	if role == "" {
		role = r.DefaultRole
		log.V(1).Info("operation=reconcileConfig, message=role default fallback", "role", role)
	}
	audience := anns[AnnoAudience]
	if audience == "" {
		audience = r.DefaultAudience
		log.V(1).Info("operation=reconcileConfig, message=audience default fallback", "audience", audience)
	}
	refresh := r.DefaultRefresh
	if v := anns[AnnoRefreshSecs]; v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			refresh = d
		} else {
			log.V(1).Info("operation=reconcileConfig, message=invalid refresh-seconds annotation; using default", "value", v, "default", r.DefaultRefresh)
		}
	}
	force := anns[AnnoForceSync] == "true"

	saName := anns[AnnoSA]
	if saName == "" {
		saName = "default"
		log.V(1).Info("operation=reconcileConfig, message=saName default fallback", "saName", saName)
	}

	log.Info("operation=reconcileConfig, message=config derived from annotations",
		"mount", mount,
		"path", path,
		"role", role,
		"audience", audience,
		"refresh", refresh,
		"forceSync", force,
		"serviceAccount", saName,
	)

	// --- Decide which keys to pull from Vault ---
	// Any Secret data value that looks like "<name>" is treated as a placeholder (unless force sync is used)
	// and will be replaced by vsec.Data["name"].
	keysToFetch := map[string]string{} // secretKey -> vaultKey
	for k, v := range sec.Data {
		// placeholderRe - regex for <placeholders>
		if m := placeholderRe.FindStringSubmatch(string(v)); m != nil {
			keysToFetch[k] = m[1]
		}
	}
	if len(keysToFetch) == 0 && !force {
		log.Info("operation=reconcileSecret, message=no placeholders detected and forceSync=false; requeue after refresh", "requeueAfter", refresh)
		return ctrl.Result{RequeueAfter: refresh}, nil
	}
	log.V(1).Info("operation=reconcileSecret, message=placeholders and force mode", "keysToFetch", keysToFetch, "forceSync", force, "keysCount", len(keysToFetch))

	// ---
	// --- 1) Request short-lived SA token via TokenRequest (aud=audience) ---
	// ---
	ttl := int64(660) // 11 minutes (AKS requires >= 10m for TokenRequest)
	log.Info("operation=reconcileTokenInit, message=requesting ServiceAccount token",
		"namespace", req.Namespace,
		"serviceAccount", saName,
		"audience", audience,
		"ttlSeconds", ttl,
	)
	jwt, err := r.requestSAToken(ctx, req.Namespace, saName, audience, ttl)
	if err != nil {
		log.Error(err, "token request failed")
		r.eventf(&sec, corev1.EventTypeWarning, "TokenRequestFailed", "Failed to request SA token: %v", err)
		return ctrl.Result{}, err
	}
	log.V(2).Info("operation=reconcileToken, message=ServiceAccount token acquired", "jwtLength", len(jwt))

	// ---
	// --- 2) Init Vault client and login using Kubernetes auth ---
	// ---
	log.Info("operation=reconcileVaultBegin, message=initializing Vault client", "addr", r.VaultAddr, "k8sAuthMount", r.VaultK8sMount)
	vClient, err := r.newVaultClient()
	if err != nil {
		log.Error(err, "vault client init failed")
		r.eventf(&sec, corev1.EventTypeWarning, "VaultClientInitFailed", "Failed to init Vault client: %v", err)
		return ctrl.Result{}, err
	}

	log.Info("operation=reconcileVault, message=logging into Vault using Kubernetes auth", "role", role)
	if err := r.vaultLoginWithK8S(ctx, vClient, jwt, role); err != nil {
		log.Error(err, "operation=reconcileVault, message=vault login failed", "role", role)
		r.eventf(&sec, corev1.EventTypeWarning, "VaultLoginFailed", "Vault login failed for role %q: %v", role, err)
		return ctrl.Result{}, err
	}
	log.Info("operation=reconcileVault, message=vault login succeeded!")

	// ---
	// --- 3) Read KV v2 document from Vault ---
	// ---
	log.Info("operation=reconcileVault, message=reading KV secret from Vault", "mount", mount, "path", path)
	kv := vClient.KVv2(mount)
	vsec, err := kv.Get(ctx, path)

	if err != nil {
		log.Error(err, "operation=reconcileVault, message=vault KV get failed", "mount", mount, "path", path)
		r.eventf(&sec, corev1.EventTypeWarning, "VaultGetFailed", "KV get failed at %s/%s: %v", mount, path, err)
		return ctrl.Result{}, err
	}
	if vsec == nil {
		err := fmt.Errorf("operation=reconcileVault, message=nil response from Vault KV get")
		log.Error(err, "operation=reconcileVault, message=unexpected nil KV response")
		return ctrl.Result{}, err
	}
	if vsec.VersionMetadata != nil {
		log.V(1).Info("operation=reconcileVault, message=vault KV metadata", "version", vsec.VersionMetadata.Version, "createdTime", vsec.VersionMetadata.CreatedTime)
	}

	// ---
	// --- 4) Build patch with updated values and bookkeeping annotations ---
	// ---
	// init array for new data for secret and inject them with actual data
	newData := make(map[string][]byte, len(sec.Data))
	for key, value := range sec.Data {
		newData[key] = value // keep existing unless replaced
	}

	// newData is the array to be used to replace data in Secret
	// applied is helper array to calculate hash from in order to prevent secret leaks from hashes, logs etc.
	// this means the changed vault value would not change hash
	applied := map[string]string{} // for hashing & change summary
	for secretKey, vaultKey := range keysToFetch {
		if raw, ok := vsec.Data[vaultKey]; ok {
			// trick - JSON-marshal then attempt string-unmarshal to determine type — the values (raw) can be string, number, bool, array, or object
			// bs = byte slice
			bs, _ := json.Marshal(raw)
			var s string
			if err := json.Unmarshal(bs, &s); err == nil {
				newData[secretKey] = []byte(s)
				applied[secretKey] = digest(newData[secretKey])
				log.V(1).Info("operation=reconcileData, message=applied value from Vault", "secretKey", secretKey, "vaultKey", vaultKey, "type", "string")
			} else {
				newData[secretKey] = bs
				applied[secretKey] = digest(newData[secretKey])
				log.V(1).Info("operation=reconcileData, message=applied value from Vault", "secretKey", secretKey, "vaultKey", vaultKey, "type", "json")
			}
		} else {
			log.Info("operation=reconcileData, message=vault key missing in document; skipping", "vaultKey", vaultKey, "secretKey", secretKey)
		}
	}

	// In force mode, copy any same-named keys from the Vault doc into the Secret.
	if force {
		for secretKey := range sec.Data {
			if _, already := keysToFetch[secretKey]; already {
				continue
			}
			if raw, ok := vsec.Data[secretKey]; ok {
				bs, _ := json.Marshal(raw)
				var s string
				if err := json.Unmarshal(bs, &s); err == nil {
					newData[secretKey] = []byte(s)
					applied[secretKey] = digest(newData[secretKey])
					log.V(1).Info("operation=reconcileData, message=force applied", "vault/secretKey", secretKey, "type", "string")
				} else {
					newData[secretKey] = bs
					applied[secretKey] = digest(newData[secretKey])
					log.V(1).Info("operation=reconcileData, message=force applied", "svault/ecretKey", secretKey, "type", "json")
				}
			} else {
				log.V(2).Info("operation=reconcileData, message=force mode: no matching key in Vault for secret key", "secretKey", secretKey)
			}
		}
	}

	// Change detection via a deterministic hash of the applied keys (not the raw values).
	newHash := hashApplied(applied)
	oldHash := anns[AnnoLastHash]
	log.V(1).Info("operation=reconcileHash, message=change detection", "oldHash", oldHash, "newHash", newHash)

	currVer := fmt.Sprint(vsec.VersionMetadata.Version)
	prevVer := anns[AnnoLastVersion]

	// compare old hash with new one in order to decide whether to change the secret
	// Skip only if both “no value change” AND “no KV version change”
	if !force && prevVer == currVer && hashEqual(oldHash, applied) {
		return ctrl.Result{RequeueAfter: refresh}, nil
	}

	log.Info("operation=reconcileHash, message=patching Secret with new data and annotations")
	patch := client.MergeFrom(sec.DeepCopy())
	sec.Data = newData
	if sec.Annotations == nil {
		sec.Annotations = map[string]string{}
	}
	sec.Annotations[AnnoLastSynced] = time.Now().UTC().Format(time.RFC3339)
	if vsec != nil && vsec.VersionMetadata != nil {
		sec.Annotations[AnnoLastVersion] = fmt.Sprint(vsec.VersionMetadata.Version)
	}
	sec.Annotations[AnnoLastHash] = newHash

	if err := r.Patch(ctx, &sec, patch); err != nil {
		log.Error(err, "operation=reconcilePath, message=failed to patch Secret with synced data")
		r.eventf(&sec, corev1.EventTypeWarning, "PatchFailed", "Failed to patch Secret: %v", err)
		return ctrl.Result{}, err
	}

	log.Info("operation=reconcilePath, message=secret synced from Vault", "name", req.NamespacedName, "mount", mount, "path", path, "keysUpdated", len(applied))
	r.eventf(&sec, corev1.EventTypeNormal, "Synced", "Synced from Vault %s/%s (updated %d keys)", mount, path, len(applied))

	// Success: schedule the next refresh-based reconcile.
	return ctrl.Result{RequeueAfter: refresh}, nil
}

// --------------------------------
// k8s helper function
// --------------------------------

// requestSAToken calls the TokenRequest subresource to mint a short-lived JWT
// for the chosen ServiceAccount, with the provided audience and TTL.
func (r *SecretReconciler) requestSAToken(ctx context.Context, namespace, sa, audience string, ttlSeconds int64) (string, error) {
	log := crlog.FromContext(ctx).WithValues("sa", sa, "namespace", namespace, "audience", audience, "ttlSeconds", ttlSeconds)
	log.V(1).Info("operation=reconcileTokenBegin")
	defer log.V(1).Info("operation=reconcileTokenEnd")

	cs, err := kubernetes.NewForConfig(r.RestConfig)
	if err != nil {
		log.Error(err, "operation=reconcileToken, message=creating clientset failed")
		return "", err
	}
	tr := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: &ttlSeconds, // k8s typically enforces >= 10m
		},
	}
	tok, err := cs.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, sa, tr, metav1.CreateOptions{})
	if err != nil {
		log.Error(err, "operation=reconcileToken, message=CreateToken failed")
		return "", err
	}
	log.V(2).Info("operation=reconcileToken, message=CreateToken succeeded", "jwtLength", len(tok.Status.Token))
	return tok.Status.Token, nil
}

// newVaultClient constructs a Vault client honoring address/TLS/namespace settings.
func (r *SecretReconciler) newVaultClient() (*vaultapi.Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = r.VaultAddr
	// TLS: either load the provided CA bundle, or allow skip-verify if explicitly set.
	if r.CACertPath != "" {
		_ = cfg.ConfigureTLS(&vaultapi.TLSConfig{CACert: r.CACertPath, Insecure: r.InsecureSkipVerify})
	} else if r.InsecureSkipVerify {
		_ = cfg.ConfigureTLS(&vaultapi.TLSConfig{Insecure: true})
	}
	cli, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return cli, nil
}

// vaultLoginWithK8S exchanges the Kubernetes JWT for a Vault client token using
// the Kubernetes auth method at r.VaultK8sMount (e.g. "aks").
func (r *SecretReconciler) vaultLoginWithK8S(ctx context.Context, cli *vaultapi.Client, jwt, role string) error {
	log := crlog.FromContext(ctx).WithValues("role", role, "k8sAuthMount", r.VaultK8sMount)
	log.V(1).Info("vaultLoginWithK8S: start")
	defer log.V(1).Info("vaultLoginWithK8S: end")

	auth, err := vaultk8s.NewKubernetesAuth(
		role,
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
		err := fmt.Errorf("no client token from Vault")
		log.Error(err, "Vault login returned empty token")
		return err
	}
	log.V(1).Info("Vault login returned a client token (not logged)")
	return nil
}

// --------------------------------
// hash helper function
// --------------------------------

// hashApplied creates a deterministic hash over the map of keys that were
// updated during this reconcile (values are placeholders like "<replaced-...>").
func hashApplied(m map[string]string) string {
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// hashEqual compares the previous hash annotation with the newly computed one.
func hashEqual(prev string, m map[string]string) bool {
	return prev != "" && prev == hashApplied(m)
}

// eventf emits a Kubernetes Event if an EventRecorder is configured.
func (r *SecretReconciler) eventf(obj runtime.Object, etype, reason, msgFmt string, args ...interface{}) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(obj, etype, reason, msgFmt, args...)
}

// hashes the values
func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
