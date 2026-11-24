// Package signing signs files ("blobs") with an AWS KMS key and packages the
// signatures as Sigstore bundles that cosign can verify.
//
// It signs SHA-256 digests rather than file contents, so callers can hash large
// files while streaming them and never hold a whole file in memory. The private
// key never leaves KMS: KMS receives a digest and returns a signature.
//
// Verify the output with the key's public key (cosign public-key --key
// awskms:///<key>) and no transparency log:
//
//	cosign verify-blob --key cosign.pub --bundle <file>.sigstore.json --insecure-ignore-tlog <file>
//	cosign verify-blob-attestation --key cosign.pub --bundle <attestation>.sigstore.json \
//	  --type slsaprovenance1 --insecure-ignore-tlog <file>
package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	intoto "github.com/in-toto/attestation/go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// InTotoPayloadType is the DSSE payload type of an in-toto statement.
	InTotoPayloadType = "application/vnd.in-toto+json"
)

// KMSAPI is the subset of the KMS client the Signer uses.
type KMSAPI interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// Signer signs SHA-256 digests with an ECDSA P-256 key held in AWS KMS.
type Signer struct {
	kms       KMSAPI
	keyARN    string
	publicKey *ecdsa.PublicKey
	hint      string
}

// NewSigner loads the public key of keyID (a key ID, ARN, or alias). Later
// signing calls use the key ARN KMS resolved here, so repointing an alias
// can't silently switch keys mid-flight.
func NewSigner(ctx context.Context, client KMSAPI, keyID string) (*Signer, error) {
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("get public key for %s: %w", keyID, err)
	}
	if out.KeySpec != kmstypes.KeySpecEccNistP256 || out.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("key %s is %s/%s, want %s/%s", keyID, out.KeySpec, out.KeyUsage, kmstypes.KeySpecEccNistP256, kmstypes.KeyUsageTypeSignVerify)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key for %s: %w", keyID, err)
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || ecdsaPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("key %s is not an ECDSA P-256 key", keyID)
	}
	if out.KeyId == nil {
		return nil, fmt.Errorf("KMS returned no key ARN for %s", keyID)
	}

	// Same fingerprint format sigstore-go uses for public key hints.
	fingerprint := sha256.Sum256(out.PublicKey)
	return &Signer{
		kms:       client,
		keyARN:    *out.KeyId,
		publicKey: ecdsaPub,
		hint:      base64.StdEncoding.EncodeToString(fingerprint[:]),
	}, nil
}

// PublicKey returns the key that verifies this Signer's signatures.
func (s *Signer) PublicKey() *ecdsa.PublicKey {
	return s.publicKey
}

// SignBlob returns a Sigstore bundle (JSON) with a signature over the file
// whose SHA-256 digest is given. Verify it with cosign verify-blob --bundle.
func (s *Signer) SignBlob(ctx context.Context, sha256Digest []byte) ([]byte, error) {
	if len(sha256Digest) != sha256.Size {
		return nil, fmt.Errorf("digest is %d bytes, want a %d-byte SHA-256 digest", len(sha256Digest), sha256.Size)
	}
	sig, err := s.signDigest(ctx, sha256Digest)
	if err != nil {
		return nil, err
	}
	bundle := s.newBundle()
	bundle.Content = &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: protocommon.HashAlgorithm_SHA2_256,
				Digest:    sha256Digest,
			},
			Signature: sig,
		},
	}
	return protojson.Marshal(bundle)
}

// SignStatement returns a Sigstore bundle (JSON) with a DSSE envelope around
// the in-toto statement. Verify it with cosign verify-blob-attestation --bundle.
func (s *Signer) SignStatement(ctx context.Context, statement *intoto.Statement) ([]byte, error) {
	if err := statement.Validate(); err != nil {
		return nil, fmt.Errorf("invalid in-toto statement: %w", err)
	}
	payload, err := protojson.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("marshal in-toto statement: %w", err)
	}
	digest := sha256.Sum256(PreAuthEncoding(InTotoPayloadType, payload))
	sig, err := s.signDigest(ctx, digest[:])
	if err != nil {
		return nil, err
	}
	bundle := s.newBundle()
	bundle.Content = &protobundle.Bundle_DsseEnvelope{
		DsseEnvelope: &protodsse.Envelope{
			Payload:     payload,
			PayloadType: InTotoPayloadType,
			Signatures:  []*protodsse.Signature{{Sig: sig}},
		},
	}
	return protojson.Marshal(bundle)
}

// PreAuthEncoding is the DSSE v1 pre-authentication encoding: the bytes a
// DSSE signature actually covers.
func PreAuthEncoding(payloadType string, payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
}

func (s *Signer) newBundle() *protobundle.Bundle {
	return &protobundle.Bundle{
		MediaType: bundleMediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{Hint: s.hint},
			},
		},
	}
}

func (s *Signer) signDigest(ctx context.Context, digest []byte) ([]byte, error) {
	out, err := s.kms.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyARN,
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms sign with %s: %w", s.keyARN, err)
	}
	// Never publish a signature the expected public key can't verify.
	if !ecdsa.VerifyASN1(s.publicKey, digest, out.Signature) {
		return nil, errors.New("signature from KMS does not verify with the key's public key")
	}
	return out.Signature, nil
}
