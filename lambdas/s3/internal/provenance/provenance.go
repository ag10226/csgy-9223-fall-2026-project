// Package provenance builds the in-toto statement that describes where an
// uploaded file came from. cosign signs it and wraps it in a Sigstore bundle;
// this package only decides what the statement says.
//
// It uses only Go's standard library, so it can be unit-tested without AWS.
package provenance

import (
	"encoding/hex"
	"encoding/json"
	"time"
)

// SLSAProvenanceV1 is the predicate type for SLSA provenance v1.
// Verify with: cosign verify-blob-attestation --type slsaprovenance1 ...
const SLSAProvenanceV1 = "https://slsa.dev/provenance/v1"

// BuildType identifies our system inside the provenance document.
const BuildType = "https://github.com/ag10226/csgy-9223-fall-2026-project/lambdas/s3@v1"

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
func BuildStatement(sha256Digest []byte, up UploadInfo, run RunInfo) ([]byte, error) {
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

	return json.Marshal(statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []subject{{
			Name:   up.Key,
			Digest: map[string]string{"sha256": hex.EncodeToString(sha256Digest)},
		}},
		PredicateType: SLSAProvenanceV1,
		Predicate:     predicate,
	})
}
