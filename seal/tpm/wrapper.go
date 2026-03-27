// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build linux

package tpm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const WrapperTypeTPM = wrapping.WrapperType("tpm")

// Wrapper implements wrapping.Wrapper for TPM 2.0 auto-unseal.
type Wrapper struct {
	seal  *tpmSeal
	keyId string
}

var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new TPM wrapper.
func NewWrapper() *Wrapper {
	return &Wrapper{}
}

// Type returns the wrapper type.
func (w *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return WrapperTypeTPM, nil
}

// KeyId returns the current key identifier.
func (w *Wrapper) KeyId(_ context.Context) (string, error) {
	return w.keyId, nil
}

// SetConfig parses the config map from the seal stanza.
func (w *Wrapper) SetConfig(_ context.Context, opts ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	options, err := wrapping.GetOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("parse options: %w", err)
	}

	configMap := options.WithConfigMap

	var (
		tpmPath    string
		keyLabel   string
		pcrIndexes []int
	)

	if v, ok := configMap["tpm_path"]; ok {
		tpmPath = v
	}
	if v, ok := configMap["key_label"]; ok {
		keyLabel = v
	}
	if v, ok := configMap["pcr_indexes"]; ok && v != "" {
		for _, s := range strings.Split(v, ",") {
			idx, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("invalid pcr_indexes value %q: %w", s, err)
			}
			if idx < 0 || idx > 23 {
				return nil, fmt.Errorf("pcr_indexes value %d out of range (0-23)", idx)
			}
			pcrIndexes = append(pcrIndexes, idx)
		}
	}

	w.seal = newTPMSeal(tpmPath, pcrIndexes, keyLabel)

	h := sha256.Sum256([]byte(w.seal.keyLabel + w.seal.tpmPath))
	w.keyId = fmt.Sprintf("tpm-%x", h[:8])

	return &wrapping.WrapperConfig{
		Metadata: map[string]string{
			"tpm_path":  w.seal.tpmPath,
			"key_label": w.seal.keyLabel,
			"key_id":    w.keyId,
		},
	}, nil
}

// Init is called during core initialization.
func (w *Wrapper) Init(_ context.Context, _ ...wrapping.Option) error {
	return nil
}

// Finalize is called during shutdown.
func (w *Wrapper) Finalize(_ context.Context, _ ...wrapping.Option) error {
	return nil
}

// Encrypt seals plaintext to the TPM and packs the result into a BlobInfo.
func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, _ ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if w.seal == nil {
		return nil, fmt.Errorf("wrapper not configured; call SetConfig first")
	}

	blob, err := w.seal.encrypt(ctx, plaintext)
	if err != nil {
		return nil, fmt.Errorf("TPM seal: %w", err)
	}

	ciphertext, err := json.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("marshal sealed blob: %w", err)
	}

	return &wrapping.BlobInfo{
		Ciphertext: ciphertext,
		KeyInfo: &wrapping.KeyInfo{
			KeyId: w.keyId,
		},
	}, nil
}

// Decrypt extracts the sealed blob from BlobInfo and unseals via the TPM.
func (w *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, _ ...wrapping.Option) ([]byte, error) {
	if w.seal == nil {
		return nil, fmt.Errorf("wrapper not configured; call SetConfig first")
	}

	var blob sealedBlob
	if err := json.Unmarshal(in.Ciphertext, &blob); err != nil {
		return nil, fmt.Errorf("unmarshal sealed blob: %w", err)
	}

	plaintext, err := w.seal.decrypt(ctx, &blob)
	if err != nil {
		return nil, fmt.Errorf("TPM unseal: %w", err)
	}

	return plaintext, nil
}
