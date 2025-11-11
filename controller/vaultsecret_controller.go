package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	vssov1 "github.com/CloudHubCZ/vault-secret-sync-operator/api/v1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	crlog "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	vaultSecretFinalizer = "vaultsecret.vsso.cz/finalizer"

	conditionTypeReady    = "Ready"
	conditionReasonSynced = "Synced"
	conditionReasonError  = "SyncError"
)

// VaultSecretReconciler manages VaultSecret custom resources and ensures a core Secret exists with data sourced from Vault.
// Each VaultSecret owns a backing Secret of the same name/namespace; this controller mirrors metadata and reuses the
// Secret reconciler to inject Vault data based on annotations and placeholders.
// +kubebuilder:rbac:groups=vsso.cz,resources=vaultsecrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=vsso.cz,resources=vaultsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vsso.cz,resources=vaultsecrets/finalizers,verbs=update
type VaultSecretReconciler struct {
	*SecretReconciler
}

// -------------------------------
// SETUP entrypoint
// -------------------------------
// SetupWithManager wires the controller into the manager.
func (r *VaultSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vssov1.VaultSecret{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

// -------------------------------
// RECONCILE entrypoint
// -------------------------------
// Reconcile orchestrates creation/update of the managed Secret and keeps the status of the VaultSecret up to date.
func (r *VaultSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	log := crlog.FromContext(ctx).WithValues("vaultsecret", req.NamespacedName.String())
	log.Info("Reconciling VaultSecret start")

	// Load the VaultSecret. Missing resource means Kubernetes already deleted it.
	var vs vssov1.VaultSecret
	if err := r.Get(ctx, req.NamespacedName, &vs); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("VaultSecret not found (deleted)")
			return requeueOrNot(0, nil, log, start)
		}
		return requeueOrNot(0, err, log, start)
	}

	log.Info("Loaded VaultSecret", "generation", vs.Generation, "annotations", vs.Annotations)

	// Handle deletion before normal reconciliation to ensure cleanup happens once.
	// i.e. delete corresponding Secret for given VaultSecret
	if !vs.DeletionTimestamp.IsZero() {
		return r.finalizeVaultSecret(ctx, &vs, log, start)
	}

	// Ensure our finalizer is present so we can delete the managed Secret later.
	// so when its deleted we can delete corresponding resources as well
	if !controllerutil.ContainsFinalizer(&vs, vaultSecretFinalizer) {
		original := vs.DeepCopy()
		controllerutil.AddFinalizer(&vs, vaultSecretFinalizer)
		//log.Info("Finalizer added to VaultSecret")
		if err := r.Patch(ctx, &vs, client.MergeFrom(original)); err != nil {
			return requeueOrNot(0, err, log, start)
		}
		// Requeue to operate on the freshly patched object.
		// Reload so Status().Patch sees the updated resource version.
		if err := r.Get(ctx, req.NamespacedName, &vs); err != nil {
			return requeueOrNot(0, err, log, start)
		}
	}

	// Ensure or create the mirrored Secret.
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: vs.Name, Namespace: vs.Namespace}}
	if err := r.ensureSecret(ctx, &vs, secret, log); err != nil {
		return requeueOrNot(0, err, log, start)
	}

	secretLog := log.WithValues("secret", fmt.Sprintf("%s/%s", secret.Namespace, secret.Name))
	refresh, syncErr := r.SyncSecret(ctx, secret, secretLog)
	// If the Secret sync didn't request a requeue, fall back to the annotation on the VaultSecret.
	if refresh == 0 {
		if val := strings.TrimSpace(vs.Annotations[AnnoRefresh]); val != "" {
			if dur, err := time.ParseDuration(val); err == nil {
				refresh = dur
				log.Info("Refresh duration derived from annotation", "refresh", refresh)
			}
		}
	}
	log.Info("Sync finished", "refresh", refresh, "syncErr", syncErr)

	statusErr := r.updateStatus(ctx, &vs, secret, syncErr)
	if statusErr != nil {
		log.Error(statusErr, "failed to update status")
		// Prefer surfacing original sync error if present.
		if syncErr == nil {
			syncErr = statusErr
		}
	}

	return requeueOrNot(refresh, syncErr, log, start)
}

// -------------------------------
// FINALIZER entrypoint
// -------------------------------
// Handles cleanup (i.e. when u delete VaultSecret, delete the its Secret too)
func (r *VaultSecretReconciler) finalizeVaultSecret(ctx context.Context, vs *vssov1.VaultSecret, log logr.Logger, start time.Time) (ctrl.Result, error) {
	log.Info("Finalizing VaultSecret", "name", vs.Name, "namespace", vs.Namespace)
	if !controllerutil.ContainsFinalizer(vs, vaultSecretFinalizer) {
		return requeueOrNot(0, nil, log, start)
	}

	// Delete the managed Secret if it still exists.
	secretName := vs.Status.SecretName
	if secretName == "" {
		secretName = vs.Name
	}
	target := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: vs.Namespace}, target); err != nil {
		if !apierrors.IsNotFound(err) {
			return requeueOrNot(0, err, log, start)
		}
		log.Info("Managed Secret not found during finalization", "secret", secretName)
	} else {
		if err := r.Delete(ctx, target, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return requeueOrNot(0, err, log, start)
		}
		log.Info("Deleted managed Secret during finalization", "secret", secretName)
	}

	// Remove the finalizer to allow Kubernetes to finish the delete.
	original := vs.DeepCopy()
	controllerutil.RemoveFinalizer(vs, vaultSecretFinalizer)
	if err := r.Patch(ctx, vs, client.MergeFrom(original)); err != nil {
		return requeueOrNot(0, err, log, start)
	}
	log.Info("Finalizer removed from VaultSecret")
	return requeueOrNot(0, nil, log, start)
}

// -------------------------------
// ENSURE entrypoint
// -------------------------------
// Creates (or updates) secret managed by VaultSecret
// makes sure the managed Secret object exists with the right owner reference, metadata, and seeded data before we hand it to SyncSecret.
// It may create or mutate the Secret’s spec/annotations, which requires a general client.Client write against the Secret itself.
func (r *VaultSecretReconciler) ensureSecret(ctx context.Context, vs *vssov1.VaultSecret, secret *corev1.Secret, log logr.Logger) error {
	//log.Info("Ensuring managed Secret skeleton", "secret", fmt.Sprintf("%s/%s", secret.Namespace, secret.Name))
	mutate := func() error {
		if err := controllerutil.SetControllerReference(vs, secret, r.Scheme); err != nil {
			return err
		}

		// Mirror metadata so users can label/annotate the generated Secret.
		secret.Labels = mergeStringMap(secret.Labels, vs.Labels)

		// Copy annotations verbatim. Vault-specific ones will be honored by SyncSecret.
		secret.Annotations = mergeStringMap(secret.Annotations, vs.Annotations)
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		secret.Type = vs.Spec.Type
		if secret.Type == "" {
			secret.Type = corev1.SecretTypeOpaque
		}
		secret.Immutable = vs.Spec.Immutable

		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}

		// When the Secret is first created, seed it with the user-provided data so placeholder discovery can work.
		if secret.CreationTimestamp.IsZero() {
			for k, v := range vs.Spec.Data {
				secret.Data[k] = append([]byte(nil), v...)
			}
			for k, v := range vs.Spec.StringData {
				secret.Data[k] = []byte(v)
			}
		}

		// Preserve placeholder values so the Secret reconciler can keep deriving Vault key mappings.
		for k, v := range vs.Spec.StringData {
			if m := placeholderRe.FindStringSubmatch(v); m != nil {
				if val, exists := secret.Data[k]; !exists || len(val) == 0 {
					secret.Data[k] = []byte(v)
				}
			}
		}
		for k, raw := range vs.Spec.Data {
			if m := placeholderRe.FindStringSubmatch(string(raw)); m != nil {
				if val, exists := secret.Data[k]; !exists || len(val) == 0 {
					secret.Data[k] = append([]byte(nil), raw...)
				}
			}
		}

		return nil
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, mutate)
	if err != nil {
		return err
	}
	if op != controllerutil.OperationResultNone {
		//	log.Info("ensured managed Secret", "operation", op, "secret", fmt.Sprintf("%s/%s", secret.Namespace, secret.Name))
	} else {
		//	log.Info("managed Secret already in desired state", "secret", fmt.Sprintf("%s/%s", secret.Namespace, secret.Name))
	}
	return nil
}

// -------------------------------
// STATUS entrypoint
// -------------------------------
// works with VaultSecret API
// patches the VaultSecret status subresource with the outcome—hash, Vault version, phase, conditions—based on what SyncSecret just applied.
// Status writes are separate API calls (Status().Patch) and must be done on the CR, not the Secret.
func (r *VaultSecretReconciler) updateStatus(ctx context.Context, vs *vssov1.VaultSecret, secret *corev1.Secret, syncErr error) error {
	original := vs.DeepCopy()
	statusLog := crlog.FromContext(ctx).WithValues("vaultsecret", fmt.Sprintf("%s/%s", vs.Namespace, vs.Name))

	if secret != nil {
		latest := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, latest); err == nil {
			secret = latest
		} else if !apierrors.IsNotFound(err) {
			statusLog.Error(err, "failed to refresh managed Secret prior to status update")
		}
	}

	// Capture metadata so users can see which Secret and which Vault version were applied.
	vs.Status.ObservedGeneration = vs.Generation
	vs.Status.SecretName = secret.Name
	vs.Status.Hash = secret.Annotations[AnnoLastHash]
	vs.Status.VaultVersion = secret.Annotations[AnnoLastVersion]
	if path := vs.Annotations[AnnoPath]; path != "" {
		vs.Status.VaultPath = path
	} else if secret != nil {
		vs.Status.VaultPath = secret.Annotations[AnnoPath]
	} else {
		vs.Status.VaultPath = ""
	}

	// Convert the RFC3339 timestamp written by the Secret reconciler.
	if stamp := secret.Annotations[AnnoLastSynced]; stamp != "" {
		if parsed, err := time.Parse(time.RFC3339, stamp); err == nil {
			ts := metav1.NewTime(parsed)
			vs.Status.SyncedAt = &ts
		} else {
			vs.Status.SyncedAt = nil
		}
	} else {
		vs.Status.SyncedAt = nil
	}

	cond := metav1.Condition{
		Type:               conditionTypeReady,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             conditionReasonSynced,
		Message:            fmt.Sprintf("Secret %s/%s synced successfully", secret.Namespace, secret.Name),
		ObservedGeneration: vs.Generation,
	}
	if syncErr != nil {
		cond.Status = metav1.ConditionFalse
		cond.Reason = conditionReasonError
		cond.Message = syncErr.Error()
		vs.Status.SecretPhase = vssov1.SecretPhaseError
		vs.Status.SecretMessage = syncErr.Error()
	} else {
		vs.Status.SecretPhase = vssov1.SecretPhaseReady
		vs.Status.SecretMessage = ""
	}
	if vs.Status.SecretPhase == "" {
		vs.Status.SecretPhase = vssov1.SecretPhasePending
	}
	apimeta.SetStatusCondition(&vs.Status.Conditions, cond)
	statusLog.Info("Updated VaultSecret status", "phase", vs.Status.SecretPhase, "hash", vs.Status.Hash, "syncedAt", vs.Status.SyncedAt, "vaultVersion", vs.Status.VaultVersion, "syncErr", syncErr)

	return r.Status().Patch(ctx, vs, client.MergeFrom(original))
}

func mergeStringMap(base map[string]string, overlay map[string]string) map[string]string {
	if base == nil && len(overlay) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}
