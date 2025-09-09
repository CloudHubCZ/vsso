/*
Copyright 2024 CloudHubCZ

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"flag"
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth" // enable exec/auth providers (GCP, Azure, OIDC, ...)

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/CloudHubCZ/vault-secret-sync-operator/internal/controller"
)

var (
	// scheme (de-serialization of API objects)
	scheme = runtime.NewScheme()
	// logger with k8s metadata
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

// --------------------------------
// I/O helper functions
// --------------------------------

// getenv returns the env var value or a fallback.
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ----------------
// main
// ----------------
// wires flags, environment, and the controller manager.
func main() {
	var (
		metricsAddr                                      string
		metricsCertPath, metricsCertName, metricsCertKey string
		enableLeaderElection                             bool
		probeAddr                                        string
		secureMetrics                                    bool
		enableHTTP2                                      bool
		tlsOpts                                          []func(*tls.Config)
	)

	// --- Flags: populate operational variables for metrics, webhooks, and leader election ---
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "Address for metrics (:8443 HTTPS, :8080 HTTP, or 0 to disable).")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address for health probes.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true, "Enable leader election for controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true, "Serve metrics via HTTPS (true) or HTTP (false).")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "", "Directory containing metrics server cert/key.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "Metrics server cert filename.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "Metrics server key filename.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false, "Enable HTTP/2 for metrics/webhooks (defaults to disabled).")

	// Zap logger initiation
	zopts := zap.Options{Development: true}
	zopts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zopts)))

	// Security hardening: disable HTTP/2 unless explicitly enabled.
	// HTTP/2 has had some nasty, widely-exploited DoS vectors (most notably Rapid Reset / Stream Cancellation, CVE-2023-44487). An attacker can open lots of HTTP/2 streams and instantly reset them, forcing the server to do expensive work over and over. Many stacks—including Go’s net/http2—were affected, and this led to record-breaking DDoS attacks.
	// For an operator, the metrics don’t get any benefit from HTTP/2 (no gRPC, no large multiplexing needs), but they do increase attack surface. Disabling HTTP/2 on those internal TLS listeners is a simple, low-cost hardening step that avoids classes of issues like Rapid Reset. If you ever need HTTP/2, you can flip it back on deliberately.
	disableHTTP2 := func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} }
	if !enableHTTP2 {
		setupLog.Info("HTTP/2 disabled (use --enable-http2 to turn on)")
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// --- Metrics server ---
	// HTTP endpoint embedded by controller-runtime that exposes Prometheus metrics at /metrics
	// It is not the Kubernetes/Openshift add-on called “metrics-server” that powers kubectl/oc top
	metricsServerOptions := metricsserver.Options{BindAddress: metricsAddr, SecureServing: secureMetrics, TLSOpts: tlsOpts}
	if secureMetrics {
		// Protect the endpoint with authn/authz; RBAC is scaffolded under config/
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	if metricsCertPath != "" {
		setupLog.Info("Using provided metrics certificates", "certPath", metricsCertPath, "certName", metricsCertName, "keyName", metricsCertKey)
		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	// --- Vault-related env ---
	vaultAddr := os.Getenv("VAULT_ADDR") // REQUIRED
	if vaultAddr == "" {
		setupLog.Error(nil, "VAULT_ADDR is required but not set")
		os.Exit(1)
	}
	//vaultNamespace := os.Getenv("VAULT_NAMESPACE") // only for Vault Enterprise
	vaultK8sMount := getenv("VAULT_K8S_MOUNT", "kubernetes")
	defaultAudience := getenv("VAULT_DEFAULT_AUDIENCE", "vault")
	defaultRefreshSeconds := getenv("DEFAULT_REFRESH_SECONDS", "600")
	caCertPath := os.Getenv("VAULT_CACERT")
	insecureSkipVerify := os.Getenv("VAULT_SKIP_VERIFY") == "true"

	// Log startup summary (no secrets printed)
	setupLog.Info("Operator configuration",
		"VAULT_ADDR", vaultAddr,
		//"VAULT_NAMESPACE", vaultNamespace,
		"VAULT_K8S_MOUNT", vaultK8sMount,
		"VAULT_DEFAULT_AUDIENCE", defaultAudience,
		"DEFAULT_REFRESH_SECONDS", defaultRefreshSeconds,
		"VAULT_CACERT", caCertPath,
	)

	// --- Manager ---
	// wrapper orchestrator responsible for
	// - Builds and shares common deps: client, cache/informers, scheme, REST config, event recorder.
	// - Hosts optional servers: metrics (/metrics) and (if enabled) webhook TLS server.
	// - Runs leader election so only one instance is active when you scale replicas.
	// - Starts/stops everything and handles liveness/ready probes.
	// - Spins up each registered controller’s worker goroutines after caches have synced.
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "vault-secret-sync-operator.pmb.cz",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// --- Controller wiring ---
	// component responsible for actual work (secret reconciliation)
	// defined in secret_controller.go
	reconciler := &controller.SecretReconciler{
		Client:                mgr.GetClient(),
		Scheme:                mgr.GetScheme(),
		RestConfig:            mgr.GetConfig(), // ensures TokenRequest/TokenReview client works
		Recorder:              mgr.GetEventRecorderFor("vault-secret-sync-operator"),
		VaultAddr:             vaultAddr,
		VaultK8sMount:         vaultK8sMount,
		DefaultAudience:       defaultAudience,
		DefaultRefreshSeconds: defaultRefreshSeconds,
		CACertPath:            caCertPath,
		InsecureSkipVerify:    insecureSkipVerify,
	}

	setupLog.Info("Registering Secret controller")
	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Secret")
		os.Exit(1)
	}

	// --- Health/Ready probes ---
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
