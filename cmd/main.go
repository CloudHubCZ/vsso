package main

import (
	"crypto/tls"
	"flag"
	"os"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/CloudHubCZ/vault-secret-sync-operator/internal/controller"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustParseDurationSeconds(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	// accept plain integer seconds (e.g. "300")
	if d, err := time.ParseDuration(s + "s"); err == nil {
		return d
	}
	return def
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "Address for metrics (:8443 HTTPS, :8080 HTTP, or 0 to disable).")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address for health probes.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true, "Enable leader election for controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true, "Serve metrics via HTTPS (true) or HTTP (false).")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "Directory containing webhook cert/key.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "Webhook cert filename.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "Webhook key filename.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "", "Directory containing metrics server cert/key.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "Metrics server cert filename.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "Metrics server key filename.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false, "Enable HTTP/2 for metrics/webhooks (defaults to disabled).")

	// Zap logger in dev/debug mode
	zopts := zap.Options{Development: true}
	zopts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zopts)))

	// Disable HTTP/2 unless explicitly enabled (security hardening)
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("HTTP/2 disabled")
		c.NextProtos = []string{"http/1.1"}
	}
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Webhook server (unused controllers can still run with it configured)
	webhookServerOptions := webhook.Options{TLSOpts: tlsOpts}
	if webhookCertPath != "" {
		setupLog.Info("Using provided webhook certificates",
			"certPath", webhookCertPath, "certName", webhookCertName, "keyName", webhookCertKey)
		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}
	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics server
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if secureMetrics {
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	if metricsCertPath != "" {
		setupLog.Info("Using provided metrics certificates",
			"certPath", metricsCertPath, "certName", metricsCertName, "keyName", metricsCertKey)
		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	// ---- Read Vault-related env (with defaults) ----
	vaultAddr := os.Getenv("VAULT_ADDR") // REQUIRED
	if vaultAddr == "" {
		setupLog.Error(nil, "VAULT_ADDR is required but not set")
		os.Exit(1)
	}
	vaultNamespace := os.Getenv("VAULT_NAMESPACE")
	vaultK8sMount := getenv("VAULT_K8S_MOUNT", "kubernetes")
	defaultRole := getenv("VAULT_DEFAULT_ROLE", "vsso")
	defaultAudience := getenv("VAULT_DEFAULT_AUDIENCE", "vault")
	defaultRefresh := mustParseDurationSeconds(os.Getenv("DEFAULT_REFRESH_SECONDS"), 300*time.Second)
	caCertPath := os.Getenv("VAULT_CACERT")
	insecureSkipVerify := os.Getenv("VAULT_SKIP_VERIFY") == "true"

	// Log a clear startup summary (no secrets printed)
	setupLog.Info("Operator configuration",
		"VAULT_ADDR", vaultAddr,
		"VAULT_NAMESPACE", vaultNamespace,
		"VAULT_K8S_MOUNT", vaultK8sMount,
		"DEFAULT_ROLE", defaultRole,
		"DEFAULT_AUDIENCE", defaultAudience,
		"DEFAULT_REFRESH", defaultRefresh.String(),
		"VAULT_CACERT", caCertPath,
		"VAULT_SKIP_VERIFY", insecureSkipVerify,
		"leaderElection", enableLeaderElection,
		"metricsAddr", metricsAddr,
		"secureMetrics", secureMetrics,
		"enableHTTP2", enableHTTP2,
	)

	// ---- Manager ----
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "vault-secret-sync-operator.ppfbanka.cz",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// ---- Controller wiring (VERBOSE) ----
	reconciler := &controller.SecretReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		RestConfig:         mgr.GetConfig(), // <<< IMPORTANT: avoids nil panic in NewForConfig
		Recorder:           mgr.GetEventRecorderFor("vault-secret-sync-operator"),
		VaultAddr:          vaultAddr,
		VaultNamespace:     vaultNamespace,
		VaultK8sMount:      vaultK8sMount,
		DefaultRole:        defaultRole,
		DefaultAudience:    defaultAudience,
		DefaultRefresh:     defaultRefresh,
		CACertPath:         caCertPath,
		InsecureSkipVerify: insecureSkipVerify,
	}

	setupLog.Info("Registering Secret controller")
	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Secret")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	// ---- Health/Ready ----
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager (press Ctrl+C to stop)")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
