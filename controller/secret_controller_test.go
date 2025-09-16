package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const secretKeyPlaceholder = "<foo>"
const vaultKey = "foo"
const vaultValue = "bar"

// OK TEST - validates expected OK behaviour
func TestSecretReconcile_OK_InstrumentsAndIdempotent(t *testing.T) {
	// make zap write into test logs
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(tWriter{t: t})))

	t.Parallel()

	// Secret "before instrumentation"
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mock-secret",
			Namespace: "test-mock-namespace",
			Annotations: map[string]string{
				"vault.hashicorp.com/path":         "test-mock-app",
				"vault.hashicorp.com/refresh-time": "120s",
			},
		},
		Data: map[string][]byte{
			"password": []byte(secretKeyPlaceholder),
		},
	}

	vssoInstance, cl := initTestedController(t, secret)

	req := ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "test-mock-namespace",
		Name:      "test-mock-secret",
	}}

	// First reconcile: should instrument the Secret and schedule refresh
	res, err := vssoInstance.Reconcile(context.Background(), req)
	mustNoErr(t, err)
	approxEqualDuration(t, 120*time.Second, res.RequeueAfter, 2*time.Second)

	got := &corev1.Secret{}
	mustNoErr(t, cl.Get(context.Background(), req.NamespacedName, got))

	// Expect the controller to have written the resolved value into Data["password"] as bytes "bar".
	if v, ok := got.Data["password"]; ok {
		if !reflect.DeepEqual([]byte(vaultValue), v) {
			t.Fatalf("data.password = %q; want %q", string(v), vaultValue)
		}
	} else {
		// Optional fallback in case your implementation used StringData with the fake client
		if s := got.StringData["password"]; s != vaultValue {
			t.Fatalf("password not found in data; stringData.password = %q; want %q", s, vaultValue)
		}
	}

	ann := got.GetAnnotations()
	mustEqual(t, "test-mock-app", ann["vault.hashicorp.com/path"])
	mustEqual(t, "120s", ann["vault.hashicorp.com/refresh-time"])
	mustEqual(t, "5", ann["vault.hashicorp.com/kv-version"])

	// keys annotation should be a JSON: {"password":"foo"}
	keysJSON := ann["vault.hashicorp.com/keys"]
	if keysJSON == "" {
		t.Fatalf("missing keys annotation")
	}
	var keys map[string]string
	mustNoErr(t, json.Unmarshal([]byte(keysJSON), &keys))
	if !reflect.DeepEqual(map[string]string{"password": vaultKey}, keys) {
		t.Fatalf("keys = %+v; want map[password:foo]", keys)
	}
	if ann["vault.hashicorp.com/last-hash"] == "" {
		t.Fatalf("missing last-hash annotation")
	}
	if ann["vault.hashicorp.com/last-synced"] == "" {
		t.Fatalf("missing last-synced annotation")
	}

	prevHash := ann["vault.hashicorp.com/last-hash"]
	prevSynced := ann["vault.hashicorp.com/last-synced"]

	// Second reconcile must be idempotent (no changes), same refresh interval
	res2, err := vssoInstance.Reconcile(context.Background(), req)
	mustNoErr(t, err)
	approxEqualDuration(t, 120*time.Second, res2.RequeueAfter, 2*time.Second)

	got2 := &corev1.Secret{}
	mustNoErr(t, cl.Get(context.Background(), req.NamespacedName, got2))
	ann2 := got2.GetAnnotations()

	mustEqual(t, prevHash, ann2["vault.hashicorp.com/last-hash"])
	mustEqual(t, prevSynced, ann2["vault.hashicorp.com/last-synced"])
}

// TEST NOK - validates error on MissingPath
func TestSecretReconcile_NOK_MissingPath_NoOp(t *testing.T) {
	// make zap write into test logs
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(tWriter{t: t})))
	t.Parallel()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mock-secret",
			Namespace: "test-mock-namespace",
		},
		Data: map[string][]byte{
			"password": []byte(secretKeyPlaceholder),
		},
	}

	vssoInstance, cl := initTestedController(t, secret)
	req := ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "test-mock-namespace",
		Name:      "test-mock-secret",
	}}

	res, err := vssoInstance.Reconcile(context.Background(), req)
	mustNoErr(t, err)
	if res.RequeueAfter != 0 {
		t.Fatalf("unexpected requeue: %v", res.RequeueAfter)
	}

	got := &corev1.Secret{}
	mustNoErr(t, cl.Get(context.Background(), req.NamespacedName, got))
	data, ok := got.Data["password"]
	if !ok {
		t.Fatalf("data.password are for non-instrumented secret")
	}
	if string(data) != secretKeyPlaceholder {
		t.Fatalf("data.password were not meant to be replaced in this scenario, data=%s, expected=%s", data, base64.StdEncoding.EncodeToString([]byte(secretKeyPlaceholder)))
	}
}

// -------------------------------------------
// ----------------- helpers -----------------
// -------------------------------------------
func initTestedController(t *testing.T, secret *corev1.Secret) (SecretReconciler, client.WithWatch) {

	scheme := runtime.NewScheme()
	mustNoErr(t, clientgoscheme.AddToScheme(scheme))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	return SecretReconciler{
		Client:             cl,
		Scheme:             scheme,
		VaultAddr:          "https://vault.example",
		VaultK8sMount:      "kubernetes",
		DefaultAudience:    "vault",
		DefaultSA:          "default",
		InsecureSkipVerify: true,

		// Override only KVv2.Get. Return a KVv2-shaped payload:
		// Data: { "data": { "password": "bar" }, "metadata": {...optional...} }
		TestMockVaultGetFunc: func(ctx context.Context, mount, path string) (*api.KVSecret, error) {
			if mount != "test-mock-namespace" || path != "test-mock-app" {
				return nil, fmt.Errorf("unexpected mount/path: %s %s", mount, path)
			}
			return &api.KVSecret{
				Data: map[string]interface{}{
					// placeholder "<foo>" -> logical key "foo" -> value "bar"
					vaultKey: vaultValue,
				},
				VersionMetadata: &api.KVVersionMetadata{
					Version: 5,
				},
			}, nil
		},
	}, cl
}

// Injecting component logs into test
type tWriter struct{ t *testing.T }

func (w tWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustEqual[T comparable](t *testing.T, want, got T) {
	t.Helper()
	if want != got {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func approxEqualDuration(t *testing.T, want, got, delta time.Duration) {
	t.Helper()
	diff := want - got
	if diff < 0 {
		diff = -diff
	}
	if diff > delta {
		t.Fatalf("duration mismatch: got %v, want %v (±%v)", got, want, delta)
	}
}
