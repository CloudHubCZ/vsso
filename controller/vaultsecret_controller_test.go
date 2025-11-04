package controller

import (
	"context"
	"testing"
	"time"

	vssov1 "github.com/CloudHubCZ/vault-secret-sync-operator/api/v1"
	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// TestVaultSecretReconcileCreatesManagedSecret verifies that a VaultSecret with Vault annotations
// results in a managed Secret seeded with placeholders and Vault data, and that the controller
// requeues based on the refresh annotation while updating status fields.
func TestVaultSecretReconcileCreatesManagedSecret(t *testing.T) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(tWriter{t: t})))
	t.Parallel()

	scheme := runtime.NewScheme()
	mustNoErr(t, clientgoscheme.AddToScheme(scheme))
	mustNoErr(t, vssov1.AddToScheme(scheme))

	vs := &vssov1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: "test",
			Annotations: map[string]string{
				AnnoPath:    "apps/demo",
				AnnoRefresh: "90s",
			},
		},
		Spec: vssov1.VaultSecretSpec{
			Type: corev1.SecretTypeOpaque,
			StringData: map[string]string{
				"password": "<foo>",
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vs).WithStatusSubresource(vs).Build()

	secretReconciler := &SecretReconciler{
		Client:             cl,
		Scheme:             scheme,
		VaultAddr:          "https://vault.example",
		VaultK8sMount:      "kubernetes",
		DefaultAudience:    "vault",
		DefaultSA:          "default",
		InsecureSkipVerify: true,
		TestMockVaultGetFunc: func(ctx context.Context, mount, path string) (*api.KVSecret, error) {
			return &api.KVSecret{
				Data: map[string]interface{}{
					"foo": "bar",
				},
				VersionMetadata: &api.KVVersionMetadata{Version: 7},
			}, nil
		},
	}
	vaultReconciler := &VaultSecretReconciler{SecretReconciler: secretReconciler}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: vs.Name, Namespace: vs.Namespace}}
	res, err := vaultReconciler.Reconcile(context.Background(), req)
	mustNoErr(t, err)
	approxEqualDuration(t, 90*time.Second, res.RequeueAfter, 2*time.Second)

	secret := &corev1.Secret{}
	mustNoErr(t, cl.Get(context.Background(), req.NamespacedName, secret))
	if got := string(secret.Data["password"]); got != "bar" {
		t.Fatalf("secret data.password = %q, want %q", got, "bar")
	}
	if secret.Annotations[AnnoRefresh] != "90s" {
		t.Fatalf("secret refresh annotation = %q, want %q", secret.Annotations[AnnoRefresh], "90s")
	}
	if ownerRefs := secret.GetOwnerReferences(); len(ownerRefs) != 1 || ownerRefs[0].Name != vs.Name {
		t.Fatalf("secret ownerReferences = %+v, want VaultSecret owner", ownerRefs)
	}
	if secret.Annotations[AnnoPath] != "apps/demo" {
		t.Fatalf("secret annotation path = %s, want apps/demo", secret.Annotations[AnnoPath])
	}

	current := &vssov1.VaultSecret{}
	mustNoErr(t, cl.Get(context.Background(), req.NamespacedName, current))
	if current.Status.SecretName != vs.Name {
		t.Fatalf("status.secretName = %s, want %s", current.Status.SecretName, vs.Name)
	}
	if current.Status.Hash == "" {
		t.Fatalf("status.hash is empty")
	}
	if current.Status.VaultVersion != "7" {
		t.Fatalf("status.vaultVersion = %s, want 7", current.Status.VaultVersion)
	}
	if current.Status.SyncedAt == nil || current.Status.SyncedAt.IsZero() {
		t.Fatalf("status.syncedAt not recorded: %+v", current.Status.SyncedAt)
	}
	if current.Status.SecretPhase != vssov1.SecretPhaseReady {
		t.Fatalf("status.secretPhase = %s, want Ready", current.Status.SecretPhase)
	}
	if current.Status.SecretMessage != "" {
		t.Fatalf("status.secretMessage = %q, want empty", current.Status.SecretMessage)
	}
	cond := apimeta.FindStatusCondition(current.Status.Conditions, conditionTypeReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready condition true, got %+v", cond)
	}
	if cond.Reason != conditionReasonSynced {
		t.Fatalf("expected condition reason Synced, got %q", cond.Reason)
	}
}

// TestVaultSecretFinalizeDeletesManagedSecret exercises the finalize path: a VaultSecret marked for
// deletion should remove its managed Secret and drop the finalizer so Kubernetes can garbage-collect.
func TestVaultSecretFinalizeDeletesManagedSecret(t *testing.T) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(tWriter{t: t})))
	t.Parallel()

	scheme := runtime.NewScheme()
	mustNoErr(t, clientgoscheme.AddToScheme(scheme))
	mustNoErr(t, vssov1.AddToScheme(scheme))

	vs := &vssov1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: "test",
			Annotations: map[string]string{
				AnnoPath: "apps/demo",
			},
		},
		Spec: vssov1.VaultSecretSpec{
			StringData: map[string]string{"password": "<foo>"},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(vs).
		WithStatusSubresource(vs).
		Build()

	secretReconciler := &SecretReconciler{
		Client:             cl,
		Scheme:             scheme,
		VaultAddr:          "https://vault.example",
		VaultK8sMount:      "kubernetes",
		DefaultAudience:    "vault",
		DefaultSA:          "default",
		InsecureSkipVerify: true,
		TestMockVaultGetFunc: func(ctx context.Context, mount, path string) (*api.KVSecret, error) {
			return &api.KVSecret{
				Data: map[string]interface{}{"foo": "bar"},
				VersionMetadata: &api.KVVersionMetadata{
					Version: 1,
				},
			}, nil
		},
	}
	vaultReconciler := &VaultSecretReconciler{SecretReconciler: secretReconciler}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: vs.Name, Namespace: vs.Namespace}}

	// First reconcile to create the managed Secret.
	_, err := vaultReconciler.Reconcile(context.Background(), req)
	mustNoErr(t, err)

	current := &vssov1.VaultSecret{}
	mustNoErr(t, cl.Get(context.Background(), req.NamespacedName, current))

	now := metav1.Now()
	current.DeletionTimestamp = &now

	res, err := vaultReconciler.finalizeVaultSecret(context.Background(), current, ctrl.Log.WithName("test-finalize"), time.Now())
	mustNoErr(t, err)
	if res.RequeueAfter != 0 {
		t.Fatalf("expected no requeue during finalization, got %v", res.RequeueAfter)
	}

	secret := &corev1.Secret{}
	err = cl.Get(context.Background(), req.NamespacedName, secret)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected managed Secret to be deleted, got %v", err)
	}

	final := &vssov1.VaultSecret{}
	mustNoErr(t, cl.Get(context.Background(), req.NamespacedName, final))
	if controllerutil.ContainsFinalizer(final, vaultSecretFinalizer) {
		t.Fatalf("finalizer still present after reconciliation")
	}
}
