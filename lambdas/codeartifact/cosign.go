package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cosignattest "github.com/sigstore/cosign/v3/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	cosignsign "github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
)

const (
	signatureSuffix   = ".sigstore.json"
	attestationSuffix = ".att.sigstore.json"
	cosignTimeout     = 2 * time.Minute
)

// signBlob runs cosign sign-blob on the file at artifactPath and returns the
// Sigstore bundle. Verify it with:
//
//	cosign verify-blob --key cosign.pub --bundle <file>.sigstore.json --insecure-ignore-tlog=true <file>
func (h *Handler) signBlob(ctx context.Context, artifactPath string) ([]byte, error) {
	bundlePath := artifactPath + signatureSuffix
	_, err := cosignsign.SignBlobCmd(ctx,
		&options.RootOptions{Timeout: cosignTimeout},
		h.keyOpts(bundlePath),
		artifactPath,
		"", "", // no certificate or chain: we sign with a KMS key
		false,  // no base64 output
		"", "", // no separate signature/certificate files: everything goes in the bundle
		false, // don't upload to the public transparency log
	)
	if err != nil {
		return nil, fmt.Errorf("cosign sign-blob: %w", err)
	}
	return os.ReadFile(bundlePath)
}

// attestStatement runs cosign attest-blob on an in-toto statement and returns
// the Sigstore bundle. cosign takes the subjects from the statement, so one
// attestation can cover several files. Verify it against any of them with:
//
//	cosign verify-blob-attestation --key cosign.pub --bundle <attestation> \
//	  --type slsaprovenance1 --insecure-ignore-tlog=true <file>
func (h *Handler) attestStatement(ctx context.Context, dir string, statement []byte) ([]byte, error) {
	statementPath := filepath.Join(dir, "statement.json")
	if err := os.WriteFile(statementPath, statement, 0o600); err != nil {
		return nil, fmt.Errorf("write statement: %w", err)
	}
	bundlePath := filepath.Join(dir, "statement"+attestationSuffix)
	attest := cosignattest.AttestBlobCommand{
		KeyOpts:        h.keyOpts(bundlePath),
		StatementPath:  statementPath,
		TlogUpload:     false,
		Timeout:        cosignTimeout,
		RekorEntryType: "dsse",
	}
	// With a statement, cosign never reads the artifact, so no path is needed.
	if err := attest.Exec(ctx, ""); err != nil {
		return nil, fmt.Errorf("cosign attest-blob: %w", err)
	}
	return os.ReadFile(bundlePath)
}

// keyOpts is the cosign configuration shared by signing and attesting:
// sign with the key, write a new-format bundle, never prompt.
func (h *Handler) keyOpts(bundlePath string) options.KeyOpts {
	return options.KeyOpts{
		KeyRef:           h.keyRef,
		NewBundleFormat:  true,
		BundlePath:       bundlePath,
		SkipConfirmation: true,
	}
}
