// Package signingtest provides an in-memory KMS and sigstore-go based
// verification helpers for testing code that uses signing.
package signingtest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

const KeyARN = "arn:aws:kms:us-east-1:111122223333:key/test"

// FakeKMS is an in-memory ECDSA P-256 key behind the KMS GetPublicKey and Sign
// calls signing makes.
type FakeKMS struct {
	Key *ecdsa.PrivateKey
	// SignWith, if set, signs with a different key than GetPublicKey reports.
	SignWith *ecdsa.PrivateKey
	// KeySpec overrides the reported key spec.
	KeySpec kmstypes.KeySpec
	Signed  int
}

func NewFakeKMS(t testing.TB) *FakeKMS {
	t.Helper()
	return &FakeKMS{Key: NewKey(t), KeySpec: kmstypes.KeySpecEccNistP256}
}

func NewKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (f *FakeKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	der, err := x509.MarshalPKIXPublicKey(&f.Key.PublicKey)
	if err != nil {
		return nil, err
	}
	keyARN := KeyARN
	return &kms.GetPublicKeyOutput{
		KeyId:     &keyARN,
		KeySpec:   f.KeySpec,
		KeyUsage:  kmstypes.KeyUsageTypeSignVerify,
		PublicKey: der,
	}, nil
}

func (f *FakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	key := f.Key
	if f.SignWith != nil {
		key = f.SignWith
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, in.Message)
	if err != nil {
		return nil, err
	}
	f.Signed++
	return &kms.SignOutput{KeyId: in.KeyId, Signature: sig, SigningAlgorithm: in.SigningAlgorithm}, nil
}

// Verify checks a Sigstore bundle the way cosign does with --key and
// --insecure-ignore-tlog: the signature must verify with pub and cover the
// artifact with the given SHA-256 digest. For an attestation bundle, the
// digest must be one of the statement's subjects.
func Verify(bundleJSON []byte, pub *ecdsa.PublicKey, sha256Digest []byte) (*verify.VerificationResult, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, err
	}
	verifier, err := signature.LoadECDSAVerifier(pub, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	hint := b.GetVerificationMaterial().GetPublicKey().GetHint()
	trusted := root.NewTrustedPublicKeyMaterialFromMapping(map[string]*root.ExpiringKey{
		hint: root.NewExpiringKey(verifier, time.Time{}, time.Time{}),
	})
	v, err := verify.NewVerifier(trusted, verify.WithNoObserverTimestamps())
	if err != nil {
		return nil, err
	}
	return v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", sha256Digest), verify.WithKey()))
}
