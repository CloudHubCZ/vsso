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

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultSecretSpec defines the desired state of a VaultSecret.
type VaultSecretSpec struct {
	// Type mirrors corev1.Secret.Type.
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`

	// Data mirrors corev1.Secret.Data.
	// +optional
	Data map[string][]byte `json:"data,omitempty"`

	// StringData mirrors corev1.Secret.StringData.
	// +optional
	StringData map[string]string `json:"stringData,omitempty"`

	// Immutable mirrors corev1.Secret.Immutable.
	// +optional
	Immutable *bool `json:"immutable,omitempty"`
}

// VaultSecretStatus captures observed state about reconciled secrets.
type SecretPhase string

const (
	SecretPhasePending SecretPhase = "Pending"
	SecretPhaseReady   SecretPhase = "Ready"
	SecretPhaseError   SecretPhase = "Error"
)

type VaultSecretStatus struct {
	// ObservedGeneration tracks the most recent generation seen by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// SyncedAt is the timestamp of the most recent successful sync.
	// +optional
	SyncedAt *metav1.Time `json:"syncedAt,omitempty"`

	// VaultVersion reflects the metadata version returned by Vault.
	// +optional
	VaultVersion string `json:"vaultVersion,omitempty"`

	// SecretName records the name of the managed core Secret.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// Hash is the content hash of applied data.
	// +optional
	Hash string `json:"hash,omitempty"`

	// Conditions contains the latest reconciliation conditions.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// SecretPhase is a coarse-grained indicator whether the managed Secret
	// has been created successfully.
	// +optional
	SecretPhase SecretPhase `json:"secretPhase,omitempty"`

	// SecretMessage contains a short explanation when SecretPhase is not Ready.
	// +optional
	SecretMessage string `json:"secretMessage,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=vaultsecrets,scope=Namespaced,shortName=vs
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.status.secretName`
// +kubebuilder:printcolumn:name="Path",type=string,JSONPath=`.metadata.annotations['vault.hashicorp.com/path']`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.syncedAt`

// VaultSecret is the Schema for the VaultSecret API.
type VaultSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultSecretSpec   `json:"spec,omitempty"`
	Status VaultSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultSecretList contains a list of VaultSecret.
type VaultSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultSecret{}, &VaultSecretList{})
}
