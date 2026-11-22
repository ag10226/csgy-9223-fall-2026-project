// Command s3-signer is an AWS Lambda function that signs files uploaded to S3.
//
// For every uploaded file it:
//  1. streams the file from S3 and computes its SHA-256 digest
//  2. asks AWS KMS to sign the digest            -> <key>.sig
//  3. builds and signs a provenance attestation   -> <key>.att.json
//  4. writes both to the signatures bucket
//
// Configuration (set by Terraform as environment variables):
//
//	KMS_KEY_ARN       full ARN of the asymmetric ECC_NIST_P256 signing key
//	SIGNATURE_BUCKET  bucket where .sig and .att.json files are written
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"group12/lambdas/s3/internal/events"
	"group12/lambdas/s3/internal/signing"
)

// File endings this function writes. It never signs its own output, which
// prevents an endless loop if someone points it at the same bucket.
var outputSuffixes = []string{".sig", ".att.json"}

// Created once when the Lambda starts ("cold start") and reused afterwards.
var (
	s3Client        *s3.Client
	signer          signing.Signer
	signatureBucket string
)

func main() {
	keyARN := mustEnv("KMS_KEY_ARN")
	signatureBucket = mustEnv("SIGNATURE_BUCKET")

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("loading AWS config: %v", err)
	}
	s3Client = s3.NewFromConfig(cfg)
	signer = &kmsSigner{client: kms.NewFromConfig(cfg), keyARN: keyARN}

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
		if isOwnOutput(obj.Key) {
			log.Printf("skipping s3://%s/%s (it is a signature or attestation)", obj.Bucket, obj.Key)
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

	// 1. Stream the file from S3 and fingerprint it.
	in := &s3.GetObjectInput{Bucket: aws.String(obj.Bucket), Key: aws.String(obj.Key)}
	if obj.VersionID != "" {
		in.VersionId = aws.String(obj.VersionID) // sign exactly the version that was uploaded
	}
	out, err := s3Client.GetObject(ctx, in)
	if err != nil {
		return fmt.Errorf("downloading: %w", err)
	}
	defer out.Body.Close()

	digest, size, err := signing.Digest(out.Body)
	if err != nil {
		return err
	}

	// 2. Sign the digest with KMS.
	sigB64, err := signing.SignBlob(ctx, signer, digest)
	if err != nil {
		return err
	}

	// 3. Build and sign the attestation.
	run := signing.RunInfo{StartedOn: started}
	if lc, ok := lambdacontext.FromContext(ctx); ok {
		run.SignerID = lc.InvokedFunctionArn
		run.InvocationID = lc.AwsRequestID
	}
	stmt, err := signing.BuildStatement(digest, signing.UploadInfo{
		Bucket:    obj.Bucket,
		Key:       obj.Key,
		VersionID: obj.VersionID,
		Size:      size,
		Uploader:  obj.Uploader,
		SourceIP:  obj.SourceIP,
		EventTime: obj.EventTime,
	}, run)
	if err != nil {
		return fmt.Errorf("building attestation: %w", err)
	}
	envelope, err := signing.SignEnvelope(ctx, signer, stmt)
	if err != nil {
		return err
	}

	// 4. Save both next to each other in the signatures bucket.
	if err := put(ctx, obj.Key+".sig", []byte(sigB64), "text/plain"); err != nil {
		return err
	}
	if err := put(ctx, obj.Key+".att.json", envelope, "application/json"); err != nil {
		return err
	}

	log.Printf("signed s3://%s/%s (%d bytes, sha256 %x) -> s3://%s/%s.sig and .att.json",
		obj.Bucket, obj.Key, size, digest, signatureBucket, obj.Key)
	return nil
}

func put(ctx context.Context, key string, body []byte, contentType string) error {
	_, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(signatureBucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("uploading %s: %w", key, err)
	}
	return nil
}

// kmsSigner implements signing.Signer using AWS KMS. The private key never
// leaves KMS: we send a 32-byte digest and get a signature back.
type kmsSigner struct {
	client *kms.Client
	keyARN string
}

func (k *kmsSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	out, err := k.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(k.keyARN),
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS Sign with %s: %w", k.keyARN, err)
	}
	return out.Signature, nil
}

func isOwnOutput(key string) bool {
	for _, s := range outputSuffixes {
		if strings.HasSuffix(key, s) {
			return true
		}
	}
	return false
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("environment variable %s is not set", name)
	}
	return v
}
