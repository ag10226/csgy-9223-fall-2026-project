// Command codeartifact-signer signs and attests package versions published to
// AWS CodeArtifact. It is triggered by EventBridge "CodeArtifact Package Version
// State Change" events.
//
// For each published version it checks every asset against the hashes
// CodeArtifact reports, signs each asset and a SLSA provenance attestation
// covering all of them with a KMS key, and writes the Sigstore bundles to S3.
//
// Configuration (set by Terraform as environment variables):
//
//	KMS_KEY_ARN       full ARN of the asymmetric ECC_NIST_P256 signing key
//	SIGNATURE_BUCKET  bucket where signatures and attestations are written
//	SIGNATURE_PREFIX  key prefix for this function's objects in that bucket
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/codeartifact"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"group12/lambdas/codeartifact/internal/signing"
)

func main() {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		logger.Error("load AWS config", "error", err)
		os.Exit(1)
	}

	signer, err := signing.NewSigner(ctx, kms.NewFromConfig(cfg), mustEnv(logger, "KMS_KEY_ARN"))
	if err != nil {
		logger.Error("load signing key", "error", err)
		os.Exit(1)
	}

	h := &Handler{
		codeArtifact: codeartifact.NewFromConfig(cfg),
		s3:           s3.NewFromConfig(cfg),
		signer:       signer,
		bucket:       mustEnv(logger, "SIGNATURE_BUCKET"),
		prefix:       mustEnv(logger, "SIGNATURE_PREFIX"),
		logger:       logger,
	}
	lambda.Start(h.Handle)
}

func mustEnv(logger *slog.Logger, name string) string {
	value := os.Getenv(name)
	if value == "" {
		logger.Error("missing required environment variable", "name", name)
		os.Exit(1)
	}
	return value
}
