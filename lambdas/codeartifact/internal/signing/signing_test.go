package signing_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"group12/lambdas/codeartifact/internal/signing"
	"group12/lambdas/codeartifact/internal/signing/signingtest"
)

func newSigner(t *testing.T, fake *signingtest.FakeKMS) *signing.Signer {
	t.Helper()
	signer, err := signing.NewSigner(context.Background(), fake, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestSignBlobVerifies(t *testing.T) {
	signer := newSigner(t, signingtest.NewFakeKMS(t))
	digest := sha256.Sum256([]byte("package contents"))

	bundle, err := signer.SignBlob(context.Background(), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signingtest.Verify(bundle, signer.PublicKey(), digest[:]); err != nil {
		t.Errorf("bundle does not verify: %v", err)
	}

	other := sha256.Sum256([]byte("tampered contents"))
	if _, err := signingtest.Verify(bundle, signer.PublicKey(), other[:]); err == nil {
		t.Error("bundle verified against a different file")
	}
	otherKey := signingtest.NewKey(t)
	if _, err := signingtest.Verify(bundle, &otherKey.PublicKey, digest[:]); err == nil {
		t.Error("bundle verified with a different key")
	}
}

func TestSignStatementVerifies(t *testing.T) {
	signer := newSigner(t, signingtest.NewFakeKMS(t))
	a := sha256.Sum256([]byte("asset a"))
	b := sha256.Sum256([]byte("asset b"))
	predicate, err := structpb.NewStruct(map[string]any{"note": "test"})
	if err != nil {
		t.Fatal(err)
	}
	statement := &intoto.Statement{
		Type: intoto.StatementTypeUri,
		Subject: []*intoto.ResourceDescriptor{
			{Name: "a.tgz", Digest: map[string]string{"sha256": hex.EncodeToString(a[:])}},
			{Name: "b.whl", Digest: map[string]string{"sha256": hex.EncodeToString(b[:])}},
		},
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate:     predicate,
	}

	bundle, err := signer.SignStatement(context.Background(), statement)
	if err != nil {
		t.Fatal(err)
	}
	for _, digest := range [][32]byte{a, b} {
		if _, err := signingtest.Verify(bundle, signer.PublicKey(), digest[:]); err != nil {
			t.Errorf("attestation does not verify for subject %x: %v", digest, err)
		}
	}
	notSubject := sha256.Sum256([]byte("not a subject"))
	if _, err := signingtest.Verify(bundle, signer.PublicKey(), notSubject[:]); err == nil {
		t.Error("attestation verified for a file that is not a subject")
	}
}

func TestSignStatementRejectsInvalidStatement(t *testing.T) {
	fake := signingtest.NewFakeKMS(t)
	signer := newSigner(t, fake)
	_, err := signer.SignStatement(context.Background(), &intoto.Statement{Type: intoto.StatementTypeUri})
	if err == nil {
		t.Error("signed a statement with no subjects")
	}
	if fake.Signed != 0 {
		t.Errorf("called KMS Sign %d times for an invalid statement", fake.Signed)
	}
}

func TestNewSignerRejectsWrongKeySpec(t *testing.T) {
	fake := signingtest.NewFakeKMS(t)
	fake.KeySpec = kmstypes.KeySpecRsa2048
	if _, err := signing.NewSigner(context.Background(), fake, "alias/test"); err == nil {
		t.Error("NewSigner accepted an RSA key spec")
	}
}

func TestSignRejectsSignatureFromOtherKey(t *testing.T) {
	fake := signingtest.NewFakeKMS(t)
	signer := newSigner(t, fake)
	fake.SignWith = signingtest.NewKey(t)

	digest := sha256.Sum256([]byte("package contents"))
	_, err := signer.SignBlob(context.Background(), digest[:])
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("SignBlob() err = %v, want a verification failure", err)
	}
}

func TestSignBlobRejectsBadDigest(t *testing.T) {
	signer := newSigner(t, signingtest.NewFakeKMS(t))
	if _, err := signer.SignBlob(context.Background(), []byte("not a digest")); err == nil {
		t.Error("SignBlob accepted a digest that is not 32 bytes")
	}
}
