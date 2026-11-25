// Command s3-signer is an AWS Lambda function that signs files uploaded to S3.
//
// Signing and attestation are done by cosign's own Go code (the same code the
// cosign CLI runs), so the output is the standard Sigstore bundle format that
// cosign 3 verifies by default. For every uploaded file it:
//  1. downloads the file to /tmp and computes its SHA-256 digest
//  2. signs it with the KMS key           -> <key>.sigstore.json
//  3. signs a provenance attestation      -> <key>.att.sigstore.json
//  4. writes both bundles to the signatures bucket
//
// Configuration (set by Terraform as environment variables):
//
//	KMS_KEY_ARN       full ARN of the asymmetric ECC_NIST_P256 signing key
//	SIGNATURE_BUCKET  bucket where the bundles are written
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	cosignattest "github.com/sigstore/cosign/v3/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	cosignsign "github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws" // lets cosign use awskms:// keys

	"group12/lambdas/s3/internal/events"
	"group12/lambdas/s3/internal/provenance"
)

const (
	signatureSuffix   = ".sigstore.json"
	attestationSuffix = ".att.sigstore.json"
	cosignTimeout     = 2 * time.Minute
)

// Created once when the Lambda starts ("cold start") and reused afterwards.
var (
	s3Client        *s3.Client
	keyRef          string // cosign's name for the KMS key: awskms:///<arn>
	signatureBucket string
)

func main() {
	keyRef = "awskms:///" + mustEnv("KMS_KEY_ARN")
	signatureBucket = mustEnv("SIGNATURE_BUCKET")

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("loading AWS config: %v", err)
	}
	s3Client = s3.NewFromConfig(cfg)

	lambda.Start(handle)
}

// result is returned to whoever invoked the function (handy when testing).
type result struct {
	Signed []string `json:"signed"`
}

// handle runs once per event. An event can contain several uploaded files.
func handle(ctx context.Context, raw json.RawMessage) (result, error) {
	objects, err := events.Parse(raw)
	if err != nil {
		return result{}, err
	}

	var res result
	for _, obj := range objects {
		if strings.HasSuffix(obj.Key, signatureSuffix) || strings.HasSuffix(obj.Key, "/") {
			// Never sign our own output (prevents loops) or empty "folder" markers.
			log.Printf("skipping s3://%s/%s", obj.Bucket, obj.Key)
			continue
		}
		if err := signObject(ctx, obj); err != nil {
			// Returning an error makes Lambda retry the event automatically.
			return res, fmt.Errorf("s3://%s/%s: %w", obj.Bucket, obj.Key, err)
		}
		res.Signed = append(res.Signed, fmt.Sprintf("s3://%s/%s", obj.Bucket, obj.Key))
	}
	return res, nil
}

func signObject(ctx context.Context, obj events.Object) error {
	started := time.Now()

	// Scratch folder in /tmp, deleted when we're done.
	dir, err := os.MkdirTemp("", "signer-")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	// 1. Download the file and fingerprint it in one pass.
	artifactPath := filepath.Join(dir, path.Base(obj.Key))
	digest, size, err := download(ctx, obj, artifactPath)
	if err != nil {
		return err
	}

	// 2. Sign the file with cosign -> Sigstore bundle.
	sigBundle := filepath.Join(dir, "signature.sigstore.json")
	_, err = cosignsign.SignBlobCmd(ctx,
		&options.RootOptions{Timeout: cosignTimeout},
		keyOpts(sigBundle),
		artifactPath,
		"", "", // no certificate or chain: we sign with a KMS key
		false,  // no base64 output
		"", "", // no separate signature/certificate files: everything goes in the bundle
		false, // don't upload to the public transparency log
	)
	if err != nil {
		return fmt.Errorf("cosign sign-blob: %w", err)
	}

	// 3. Describe where the file came from, then have cosign sign that statement.
	run := provenance.RunInfo{StartedOn: started}
	if lc, ok := lambdacontext.FromContext(ctx); ok {
		run.SignerID = lc.InvokedFunctionArn
		run.InvocationID = lc.AwsRequestID
	}
	stmt, err := provenance.BuildStatement(digest, provenance.UploadInfo{
		Bucket:    obj.Bucket,
		Key:       obj.Key,
		VersionID: obj.VersionID,
		Size:      size,
		Uploader:  obj.Uploader,
		SourceIP:  obj.SourceIP,
		EventTime: obj.EventTime,
	}, run)
	if err != nil {
		return fmt.Errorf("building provenance statement: %w", err)
	}
	stmtPath := filepath.Join(dir, "statement.json")
	if err := os.WriteFile(stmtPath, stmt, 0o600); err != nil {
		return fmt.Errorf("writing statement: %w", err)
	}

	attBundle := filepath.Join(dir, "attestation.sigstore.json")
	attest := cosignattest.AttestBlobCommand{
		KeyOpts:        keyOpts(attBundle),
		StatementPath:  stmtPath,
		TlogUpload:     false,
		Timeout:        cosignTimeout,
		RekorEntryType: "dsse",
	}
	if err := attest.Exec(ctx, artifactPath); err != nil {
		return fmt.Errorf("cosign attest-blob: %w", err)
	}

	// 4. Save both bundles in the signatures bucket.
	if err := upload(ctx, obj.Key+signatureSuffix, sigBundle); err != nil {
		return err
	}
	if err := upload(ctx, obj.Key+attestationSuffix, attBundle); err != nil {
		return err
	}

	log.Printf("signed s3://%s/%s (%d bytes, sha256 %x) -> s3://%s/%s{%s,%s}",
		obj.Bucket, obj.Key, size, digest, signatureBucket, obj.Key, signatureSuffix, attestationSuffix)
	return nil
}

// keyOpts is the cosign configuration shared by signing and attesting:
// sign with the KMS key, write a new-format bundle, never prompt.
func keyOpts(bundlePath string) options.KeyOpts {
	return options.KeyOpts{
		KeyRef:           keyRef,
		NewBundleFormat:  true,
		BundlePath:       bundlePath,
		SkipConfirmation: true,
	}
}

// download streams the S3 object to dst and returns its SHA-256 and size.
func download(ctx context.Context, obj events.Object, dst string) ([]byte, int64, error) {
	in := &s3.GetObjectInput{Bucket: aws.String(obj.Bucket), Key: aws.String(obj.Key)}
	if obj.VersionID != "" {
		in.VersionId = aws.String(obj.VersionID) // sign exactly the version that was uploaded
	}
	out, err := s3Client.GetObject(ctx, in)
	if err != nil {
		return nil, 0, fmt.Errorf("downloading: %w", err)
	}
	defer out.Body.Close()

	f, err := os.Create(dst)
	if err != nil {
		return nil, 0, fmt.Errorf("creating %s: %w", dst, err)
	}
	h := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(f, h), out.Body)
	closeErr := f.Close()
	if copyErr != nil {
		return nil, 0, fmt.Errorf("downloading: %w", copyErr)
	}
	if closeErr != nil {
		return nil, 0, fmt.Errorf("saving %s: %w", dst, closeErr)
	}
	return h.Sum(nil), size, nil
}

func upload(ctx context.Context, key, srcPath string) error {
	body, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", srcPath, err)
	}
	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(signatureBucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("uploading %s: %w", key, err)
	}
	return nil
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("environment variable %s is not set", name)
	}
	return v
}
