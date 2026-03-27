// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build linux

// openbao-plugin-seal-tpm is an external KMS plugin binary for OpenBao.
// It serves the TPM 2.0 seal wrapper over gRPC using the go-kms-wrapping
// plugin protocol.
//
// By John Boero and Claude — PoC, not for production use.
package main

import (
	"log"

	gkwplugin "github.com/openbao/go-kms-wrapping/plugin/v2"

	"github.com/openbao/openbao-plugins/seal/tpm"
)

func main() {
	if err := gkwplugin.ServePlugin(tpm.NewWrapper()); err != nil {
		log.Fatalf("error serving TPM seal plugin: %v", err)
	}
}
