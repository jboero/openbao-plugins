// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build linux

// Package tpm implements a TPM 2.0 auto-unseal wrapper for OpenBao.
// The master key is sealed to the TPM's Storage Root Key, optionally
// bound to PCR values for measured boot enforcement.
//
// By John Boero and Claude — PoC, not for production use.
package tpm

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	DefaultTPMPath  = "/dev/tpmrm0"
	FallbackTPMPath = "/dev/tpm0"
)

// tpmSeal holds the core TPM seal/unseal operations.
type tpmSeal struct {
	tpmPath    string
	pcrIndexes []int
	keyLabel   string
	mu         sync.Mutex
}

func newTPMSeal(tpmPath string, pcrIndexes []int, keyLabel string) *tpmSeal {
	if tpmPath == "" {
		tpmPath = DefaultTPMPath
	}
	if keyLabel == "" {
		keyLabel = "openbao-seal"
	}
	return &tpmSeal{
		tpmPath:    tpmPath,
		pcrIndexes: pcrIndexes,
		keyLabel:   keyLabel,
	}
}

// openTPM opens the configured TPM device.
func (s *tpmSeal) openTPM() (transport.TPMCloser, error) {
	t, err := transport.OpenTPM(s.tpmPath)
	if err != nil {
		t, err = transport.OpenTPM(FallbackTPMPath)
		if err != nil {
			return nil, fmt.Errorf("open TPM %s (fallback %s): %w",
				s.tpmPath, FallbackTPMPath, err)
		}
	}
	return t, nil
}

// sealedBlob is the serialized form stored inside BlobInfo.Ciphertext.
type sealedBlob struct {
	Private   []byte `json:"private"`
	Public    []byte `json:"public"`
	PCRDigest []byte `json:"pcr_digest,omitempty"`
	Label     string `json:"label"`
}

// encrypt seals plaintext to the TPM.
func (s *tpmSeal) encrypt(_ context.Context, plaintext []byte) (*sealedBlob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tpm, err := s.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	srkResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("create SRK: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: srkResp.ObjectHandle}.Execute(tpm)

	sealTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:    true,
			FixedParent: true,
			NoDA:        true,
		},
	}

	sensitive := tpm2.TPM2BSensitiveCreate{
		Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
				Buffer: plaintext,
			}),
		},
	}

	var pcrDigest []byte

	if len(s.pcrIndexes) > 0 {
		trialResp, err := tpm2.StartAuthSession{
			SessionType: tpm2.TPMSETrial,
			AuthHash:    tpm2.TPMAlgSHA256,
		}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("start trial session: %w", err)
		}

		pcrSel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: pcrIndexesToBitmap(s.pcrIndexes),
				},
			},
		}

		_, err = tpm2.PolicyPCR{
			PolicySession: trialResp.SessionHandle,
			Pcrs:          pcrSel,
		}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("trial PolicyPCR: %w", err)
		}

		dgstResp, err := tpm2.PolicyGetDigest{
			PolicySession: trialResp.SessionHandle,
		}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("get policy digest: %w", err)
		}
		pcrDigest = dgstResp.PolicyDigest.Buffer

		tpm2.FlushContext{FlushHandle: trialResp.SessionHandle}.Execute(tpm)

		sealTemplate.AuthPolicy = tpm2.TPM2BDigest{
			Buffer: pcrDigest,
		}
		sealTemplate.ObjectAttributes.AdminWithPolicy = true
	} else {
		sealTemplate.ObjectAttributes.UserWithAuth = true
	}

	createCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkResp.ObjectHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:    tpm2.New2B(sealTemplate),
		InSensitive: sensitive,
	}

	createResp, err := createCmd.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Create (seal): %w", err)
	}

	privBytes := tpm2.Marshal(createResp.OutPrivate)
	pubBytes := tpm2.Marshal(createResp.OutPublic)

	return &sealedBlob{
		Private:   privBytes,
		Public:    pubBytes,
		PCRDigest: pcrDigest,
		Label:     s.keyLabel,
	}, nil
}

// decrypt unseals the blob using the local TPM.
func (s *tpmSeal) decrypt(_ context.Context, blob *sealedBlob) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tpm, err := s.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	srkResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("create SRK: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: srkResp.ObjectHandle}.Execute(tpm)

	outPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](blob.Private)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private: %w", err)
	}
	outPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](blob.Public)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public: %w", err)
	}

	loadResp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkResp.ObjectHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: *outPrivate,
		InPublic:  *outPublic,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Load: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadResp.ObjectHandle}.Execute(tpm)

	var authSession tpm2.Session
	if len(blob.PCRDigest) > 0 && len(s.pcrIndexes) > 0 {
		sess, cleanup, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, fmt.Errorf("start policy session: %w", err)
		}
		defer cleanup()

		pcrSel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: pcrIndexesToBitmap(s.pcrIndexes),
				},
			},
		}

		_, err = tpm2.PolicyPCR{
			PolicySession: sess.Handle(),
			Pcrs:          pcrSel,
		}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("PolicyPCR failed — boot measurements may have changed: %w", err)
		}

		authSession = sess
	} else {
		authSession = tpm2.PasswordAuth(nil)
	}

	unsealResp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Auth:   authSession,
		},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Unseal: %w (if PCR-bound, boot measurements may have changed)", err)
	}

	return unsealResp.OutData.Buffer, nil
}

// pcrIndexesToBitmap converts PCR index list to TPM PCR selection bitmap.
func pcrIndexesToBitmap(indexes []int) []byte {
	bitmap := make([]byte, 3)
	for _, idx := range indexes {
		if idx >= 0 && idx < 24 {
			bitmap[idx/8] |= 1 << (idx % 8)
		}
	}
	return bitmap
}
