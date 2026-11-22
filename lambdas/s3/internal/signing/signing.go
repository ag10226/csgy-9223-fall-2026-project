// Package signing holds the core supply-chain logic for the S3 signer:
// fingerprint a file, sign it, and build a signed attestation about it.
//
// It only uses Go's standard library, so it can be unit-tested on any
// machine without AWS. The actual signing is done by whatever implements
// the Signer interface: AWS KMS in production, a local test key in tests.
//
// The output formats match what cosign expects, so the results can be
// checked with `cosign verify-blob` and `cosign verify-blob-attestation`.
package signing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Signer signs a SHA-256 digest and returns an ECDSA signature in ASN.1 DER
// form. AWS KMS returns exactly this format for ECDSA_SHA_256 keys.
type Signer interface {
	SignDigest(ctx context.Context, digest []byte) ([]byte, error)
}

// Digest reads r to the end and returns its SHA-256 hash and size in bytes.
// It streams, so even a large file never has to fit in memory.
func Digest(r io.Reader) (sum []byte, size int64, err error) {
	h := sha256.New()
	size, err = io.Copy(h, r)
	if err != nil {
		return nil, 0, fmt.Errorf("reading artifact: %w", err)
	}
	return h.Sum(nil), size, nil
}

// SignBlob signs a file's digest and returns the signature as base64 text.
// This is the same format `cosign sign-blob` writes to a .sig file.
func SignBlob(ctx context.Context, s Signer, digest []byte) (string, error) {
	sig, err := s.SignDigest(ctx, digest)
	if err != nil {
		return "", fmt.Errorf("signing artifact: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// ---------- Attestation (in-toto statement inside a DSSE envelope) ----------

// InTotoPayloadType is the DSSE payload type cosign expects for attestations.
const InTotoPayloadType = "application/vnd.in-toto+json"

// SLSAProvenanceV1 is the predicate type for SLSA provenance v1.
// Verify with: cosign verify-blob-attestation --type slsaprovenance1 ...
const SLSAProvenanceV1 = "https://slsa.dev/provenance/v1"

// BuildType identifies our system inside the provenance document.
const BuildType = "https://github.com/group12/supply-chain-signer/s3@v1"

// UploadInfo is what we know about how the artifact arrived in S3.
type UploadInfo struct {
	Bucket    string
	Key       string
	VersionID string
	Size      int64
	Uploader  string    // IAM principal that uploaded the file, if S3 told us
	SourceIP  string    // IP address the upload came from, if S3 told us
	EventTime time.Time // when S3 says the upload happened
}

// RunInfo is what we know about this run of the signer.
type RunInfo struct {
	SignerID     string    // ARN of the Lambda function doing the signing
	InvocationID string    // Lambda request ID, useful for finding logs
	StartedOn    time.Time // when signing started
}

type statement struct {
	Type          string      `json:"_type"`
	Subject       []subject   `json:"subject"`
	PredicateType string      `json:"predicateType"`
	Predicate     interface{} `json:"predicate"`
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// BuildStatement creates the in-toto statement: "this file, with this
// SHA-256, arrived in this bucket, uploaded by this principal, and was
// processed by this signer at this time".
func BuildStatement(digest []byte, up UploadInfo, run RunInfo) ([]byte, error) {
	external := map[string]interface{}{
		"bucket": up.Bucket,
		"key":    up.Key,
		"size":   up.Size,
	}
	if up.VersionID != "" {
		external["versionId"] = up.VersionID
	}

	internal := map[string]interface{}{}
	if up.Uploader != "" {
		internal["uploader"] = up.Uploader
	}
	if up.SourceIP != "" {
		internal["sourceIp"] = up.SourceIP
	}
	if !up.EventTime.IsZero() {
		internal["uploadedOn"] = up.EventTime.UTC().Format(time.RFC3339)
	}

	predicate := map[string]interface{}{
		"buildDefinition": map[string]interface{}{
			"buildType":          BuildType,
			"externalParameters": external,
			"internalParameters": internal,
		},
		"runDetails": map[string]interface{}{
			"builder": map[string]interface{}{"id": run.SignerID},
			"metadata": map[string]interface{}{
				"invocationId": run.InvocationID,
				"startedOn":    run.StartedOn.UTC().Format(time.RFC3339),
			},
		},
	}

	st := statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []subject{{
			Name:   up.Key,
			Digest: map[string]string{"sha256": hex.EncodeToString(digest)},
		}},
		PredicateType: SLSAProvenanceV1,
		Predicate:     predicate,
	}
	return json.Marshal(st)
}

// Envelope is a DSSE envelope: the signed wrapper cosign uses for attestations.
type Envelope struct {
	PayloadType string              `json:"payloadType"`
	Payload     string              `json:"payload"` // base64 of the statement
	Signatures  []EnvelopeSignature `json:"signatures"`
}

// EnvelopeSignature is one signature inside a DSSE envelope.
type EnvelopeSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64 of the DER signature
}

// PAE is DSSE's "pre-authentication encoding". The signature covers this
// encoding (not the raw payload), so an attacker can't swap the payload type.
// Spec: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
func PAE(payloadType string, payload []byte) []byte {
	header := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	return append([]byte(header), payload...)
}

// SignEnvelope signs an in-toto statement and returns the DSSE envelope as JSON.
func SignEnvelope(ctx context.Context, s Signer, statementJSON []byte) ([]byte, error) {
	sum := sha256.Sum256(PAE(InTotoPayloadType, statementJSON))
	sig, err := s.SignDigest(ctx, sum[:])
	if err != nil {
		return nil, fmt.Errorf("signing attestation: %w", err)
	}
	env := Envelope{
		PayloadType: InTotoPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(statementJSON),
		Signatures:  []EnvelopeSignature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	return json.Marshal(env)
}
