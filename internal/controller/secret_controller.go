// controllers/secret_controller.go
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

const (
	AnnoPath        = "vault.ppfbanka.cz/path"
	AnnoMount       = "vault.ppfbanka.cz/mount"
	AnnoRole        = "vault.ppfbanka.cz/role"
	AnnoSA          = "vault.ppfbanka.cz/service-account"
	AnnoAudience    = "vault.ppfbanka.cz/audience"
	AnnoRefreshSecs = "vault.ppfbanka.cz/refresh-seconds"
	AnnoForceSync   = "vault.ppfbanka.cz/force-sync"
	AnnoLastSynced  = "vault.ppfbanka.cz/last-synced"
	AnnoLastVersion = "vault.ppfbanka.cz/kv-version"
	AnnoLastHash    = "vault.ppfbanka.cz/last-hash"
)

var placeholderRe = regexp.MustCompile(`^<([A-Za-z0-9_.-]+)>$`)

// SecretReconciler reconciles core/v1 Secrets with our annotations.
type SecretReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	RestConfig *rest.Config
	Recorder   record.EventRecorder // optional; set via mgr.GetEventRecorderFor(...)

	VaultAddr          string
	VaultNamespace     string // Vault Enterprise namespace (optional)
	VaultK8sMount      string // auth mount, e.g., "kubernetes"
	DefaultRole        string
	DefaultAudience    string
	DefaultRefresh     time.Duration
	CACertPath         string
	InsecureSkipVerify bool
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Only reconcile Secrets that carry the path annotation
	pred := predicate.NewPredicateFuncs(func(o client.Object) bool {
		_, ok := o.GetAnnotations()[AnnoPath]
		return ok
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}, builder.WithPredicates(pred)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 4}).
		Complete(r)
}

func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	log := crlog.FromContext(ctx).WithValues(
		"secret", req.NamespacedName.String(),
	)

	log.Info("reconcile: start")
	defer func() {
		log.Info("reconcile: end", "duration", time.Since(start))
	}()

	// Fetch secret
	var sec corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &sec); err != nil {
		if errors.IsNotFound(err) {
			log.Info("secret not found; likely deleted, nothing to do")
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to GET Secret from API")
		return ctrl.Result{}, err
	}
	if sec.DeletionTimestamp != nil {
		log.Info("secret has DeletionTimestamp; skipping")
		return ctrl.Result{}, nil
	}

	// Read annotations and config
	anns := sec.GetAnnotations()
	if anns == nil {
		log.V(1).Info("no annotations present; skipping")
		return ctrl.Result{}, nil // filtered, but be safe
	}
	path := anns[AnnoPath]
	if path == "" {
		log.V(1).Info("required annotation missing; skipping", "annotation", AnnoPath)
		return ctrl.Result{}, nil
	}
	mount := anns[AnnoMount]
	if mount == "" {
		mount = sec.GetNamespace()
	}
	role := anns[AnnoRole]
	if role == "" {
		role = r.DefaultRole
	}
	audience := anns[AnnoAudience]
	if audience == "" {
		audience = r.DefaultAudience
	}
	refresh := r.DefaultRefresh
	if v := anns[AnnoRefreshSecs]; v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			refresh = d
		} else {
			log.V(1).Info("invalid refresh-seconds annotation; using default", "value", v, "default", r.DefaultRefresh)
		}
	}
	force := anns[AnnoForceSync] == "true"
	saName := anns[AnnoSA]
	if saName == "" {
		saName = "default"
	}

	log.Info("config derived from annotations",
		"mount", mount,
		"path", path,
		"role", role,
		"audience", audience,
		"refresh", refresh,
		"forceSync", force,
		"serviceAccount", saName,
	)

	// Determine which keys require filling from Vault
	keysToFetch := map[string]string{} // secretKey -> vaultKey
	for k, v := range sec.Data {
		val := string(v)
		if m := placeholderRe.FindStringSubmatch(val); m != nil {
			keysToFetch[k] = m[1]
		}
	}
	if len(keysToFetch) == 0 && !force {
		log.Info("no placeholders detected and forceSync=false; requeue after refresh", "requeueAfter", refresh)
		return ctrl.Result{RequeueAfter: refresh}, nil
	}
	log.V(1).Info("placeholders and force mode", "keysToFetch", keysToFetch, "forceSync", force, "keysCount", len(keysToFetch))

	// 1) Request a short-lived JWT for the chosen ServiceAccount (TokenRequest)
	log.Info("requesting ServiceAccount token",
		"namespace", req.Namespace,
		"serviceAccount", saName,
		"audience", audience,
		"ttlSeconds", 300,
	)
	jwt, err := r.requestSAToken(ctx, req.Namespace, saName, audience, 660)
	if err != nil {
		log.Error(err, "token request failed")
		r.eventf(&sec, corev1.EventTypeWarning, "TokenRequestFailed", "Failed to request SA token: %v", err)
		return ctrl.Result{RequeueAfter: refresh}, err
	}
	log.V(2).Info("ServiceAccount token acquired", "jwtLength", len(jwt))

	// 2) Login to Vault via k8s auth
	log.Info("initializing Vault client",
		"addr", r.VaultAddr,
		"namespace", r.VaultNamespace,
		"k8sAuthMount", r.VaultK8sMount,
	)
	vClient, err := r.newVaultClient()
	if err != nil {
		log.Error(err, "vault client init failed")
		r.eventf(&sec, corev1.EventTypeWarning, "VaultClientInitFailed", "Failed to init Vault client: %v", err)
		return ctrl.Result{RequeueAfter: refresh}, err
	}

	log.Info("logging into Vault using Kubernetes auth", "role", role)
	if err := r.vaultLoginWithK8S(ctx, vClient, jwt, role); err != nil {
		log.Error(err, "vault login failed", "role", role)
		r.eventf(&sec, corev1.EventTypeWarning, "VaultLoginFailed", "Vault login failed for role %q: %v", role, err)
		return ctrl.Result{RequeueAfter: refresh}, err
	}
	log.Info("vault login succeeded")

	// 3) Read from KV v2
	log.Info("reading KV secret from Vault", "mount", mount, "path", path)
	kv := vClient.KVv2(mount)
	vsec, err := kv.Get(ctx, path)
	if err != nil {
		log.Error(err, "vault KV get failed", "mount", mount, "path", path)
		r.eventf(&sec, corev1.EventTypeWarning, "VaultGetFailed", "KV get failed at %s/%s: %v", mount, path, err)
		return ctrl.Result{RequeueAfter: refresh}, err
	}
	if vsec == nil {
		err := fmt.Errorf("nil response from Vault KV get")
		log.Error(err, "unexpected nil KV response")
		return ctrl.Result{RequeueAfter: refresh}, err
	}
	if vsec.VersionMetadata != nil {
		log.V(1).Info("vault KV metadata", "version", vsec.VersionMetadata.Version, "createdTime", vsec.VersionMetadata.CreatedTime)
	}

	// Prepare patch
	newData := make(map[string][]byte, len(sec.Data))
	for k, v := range sec.Data {
		newData[k] = v // default keep existing
	}

	applied := map[string]string{} // for hashing & change summary
	for secretKey, vaultKey := range keysToFetch {
		if raw, ok := vsec.Data[vaultKey]; ok {
			bs, _ := json.Marshal(raw)
			var s string
			if err := json.Unmarshal(bs, &s); err == nil {
				newData[secretKey] = []byte(s)
				applied[secretKey] = "<replaced-from-vault>"
				log.V(1).Info("applied value from Vault", "secretKey", secretKey, "vaultKey", vaultKey, "type", "string")
			} else {
				newData[secretKey] = bs
				applied[secretKey] = "<replaced-from-vault:json>"
				log.V(1).Info("applied value from Vault", "secretKey", secretKey, "vaultKey", vaultKey, "type", "json")
			}
		} else {
			log.Info("vault key missing in document; skipping", "vaultKey", vaultKey, "secretKey", secretKey)
		}
	}

	// If force=true, also set values for any keys that exist in Vault with same name
	if force {
		for k := range sec.Data {
			if _, already := keysToFetch[k]; already {
				continue
			}
			if raw, ok := vsec.Data[k]; ok {
				bs, _ := json.Marshal(raw)
				var s string
				if err := json.Unmarshal(bs, &s); err == nil {
					newData[k] = []byte(s)
					applied[k] = "<replaced-from-vault>"
					log.V(1).Info("force applied", "secretKey", k, "vaultKey", k, "type", "string")
				} else {
					newData[k] = bs
					applied[k] = "<replaced-from-vault:json>"
					log.V(1).Info("force applied", "secretKey", k, "vaultKey", k, "type", "json")
				}
			} else {
				log.V(2).Info("force mode: no matching key in Vault for secret key", "secretKey", k)
			}
		}
	}

	newHash := hashApplied(applied)
	oldHash := anns[AnnoLastHash]
	log.V(1).Info("change detection", "oldHash", oldHash, "newHash", newHash)

	// Skip update if nothing changed
	if hashEqual(oldHash, applied) {
		log.Info("no changes to apply; requeue after refresh", "requeueAfter", refresh)
		return ctrl.Result{RequeueAfter: refresh}, nil
	}

	log.Info("patching Secret with new data and annotations")
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
		log.Error(err, "failed to patch Secret with synced data")
		r.eventf(&sec, corev1.EventTypeWarning, "PatchFailed", "Failed to patch Secret: %v", err)
		return ctrl.Result{RequeueAfter: refresh}, err
	}

	log.Info("secret synced from Vault",
		"name", req.NamespacedName,
		"mount", mount,
		"path", path,
		"keysUpdated", len(applied),
	)
	r.eventf(&sec, corev1.EventTypeNormal, "Synced", "Synced from Vault %s/%s (updated %d keys)", mount, path, len(applied))

	return ctrl.Result{RequeueAfter: refresh}, nil
}

func (r *SecretReconciler) requestSAToken(ctx context.Context, namespace, sa, audience string, ttlSeconds int64) (string, error) {
	log := crlog.FromContext(ctx).WithValues("sa", sa, "namespace", namespace, "audience", audience, "ttlSeconds", ttlSeconds)
	log.V(1).Info("requestSAToken: start")
	defer log.V(1).Info("requestSAToken: end")

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
	log.V(2).Info("CreateToken succeeded", "jwtLength", len(tok.Status.Token))
	return tok.Status.Token, nil
}

func (r *SecretReconciler) newVaultClient() (*vaultapi.Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = r.VaultAddr
	// Note: cfg.Error is deprecated in newer clients; we keep a noop for compatibility
	if r.CACertPath != "" {
		_ = cfg.ConfigureTLS(&vaultapi.TLSConfig{CACert: r.CACertPath, Insecure: r.InsecureSkipVerify})
	} else if r.InsecureSkipVerify {
		_ = cfg.ConfigureTLS(&vaultapi.TLSConfig{Insecure: true})
	}
	cli, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if r.VaultNamespace != "" {
		cli.SetNamespace(r.VaultNamespace)
	}
	return cli, nil
}

func (r *SecretReconciler) vaultLoginWithK8S(ctx context.Context, cli *vaultapi.Client, jwt, role string) error {
	log := crlog.FromContext(ctx).WithValues("role", role, "k8sAuthMount", r.VaultK8sMount)
	log.V(1).Info("vaultLoginWithK8S: start")
	defer log.V(1).Info("vaultLoginWithK8S: end")

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
		err := fmt.Errorf("no client token from Vault")
		log.Error(err, "Vault login returned empty token")
		return err
	}
	log.V(1).Info("Vault login returned a client token (not logged)")
	return nil
}

func hashApplied(m map[string]string) string {
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hashEqual(prev string, m map[string]string) bool {
	return prev != "" && prev == hashApplied(m)
}

func (r *SecretReconciler) eventf(obj runtime.Object, etype, reason, msgFmt string, args ...interface{}) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(obj, etype, reason, msgFmt, args...)
}
