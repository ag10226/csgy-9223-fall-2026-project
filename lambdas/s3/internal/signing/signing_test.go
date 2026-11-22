package signing

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// localSigner stands in for AWS KMS in tests. It uses the same key type
// (ECDSA P-256) and returns the same DER format KMS does.
type localSigner struct{ key *ecdsa.PrivateKey }

func newLocalSigner(t *testing.T) *localSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &localSigner{key: k}
}

func (l *localSigner) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, l.key, digest)
}

func TestDigestMatchesSHA256(t *testing.T) {
	data := []byte("hello supply chain")
	sum, size, err := Digest(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	if !bytes.Equal(sum, want[:]) {
		t.Fatalf("digest mismatch")
	}
	if size != int64(len(data)) {
		t.Fatalf("size = %d, want %d", size, len(data))
	}
}

func TestSignBlobVerifiesAndDetectsTampering(t *testing.T) {
	s := newLocalSigner(t)
	ctx := context.Background()

	original := []byte("pretend this is app.exe")
	sum, _, _ := Digest(bytes.NewReader(original))

	sigB64, err := SignBlob(ctx, s, sum)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}

	if !ecdsa.VerifyASN1(&s.key.PublicKey, sum, sig) {
		t.Fatal("signature did not verify against the original file")
	}

	tampered := []byte("pretend this is app.exE")
	tsum, _, _ := Digest(bytes.NewReader(tampered))
	if ecdsa.VerifyASN1(&s.key.PublicKey, tsum, sig) {
		t.Fatal("signature verified against a TAMPERED file; it must not")
	}
}

func TestStatementHasSubjectDigestAndProvenance(t *testing.T) {
	sum := sha256.Sum256([]byte("artifact"))
	up := UploadInfo{
		Bucket: "artifacts", Key: "builds/app.exe", Size: 8,
		Uploader: "AWS:AIDAEXAMPLE", SourceIP: "203.0.113.7",
		EventTime: time.Date(2026, 11, 22, 15, 0, 0, 0, time.UTC),
	}
	run := RunInfo{SignerID: "arn:aws:lambda:us-east-1:111122223333:function:s3-signer", InvocationID: "req-1", StartedOn: time.Now()}

	raw, err := BuildStatement(sum[:], up, run)
	if err != nil {
		t.Fatal(err)
	}

	var st struct {
		Type    string `json:"_type"`
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		PredicateType string                 `json:"predicateType"`
		Predicate     map[string]interface{} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("_type = %q", st.Type)
	}
	if len(st.Subject) != 1 || st.Subject[0].Name != "builds/app.exe" {
		t.Fatalf("subject = %+v", st.Subject)
	}
	if st.Subject[0].Digest["sha256"] != hex.EncodeToString(sum[:]) {
		t.Errorf("subject digest does not match the file")
	}
	if st.PredicateType != SLSAProvenanceV1 {
		t.Errorf("predicateType = %q", st.PredicateType)
	}
	if !strings.Contains(string(raw), "AWS:AIDAEXAMPLE") {
		t.Errorf("uploader missing from provenance")
	}
}

func TestEnvelopeSignatureVerifies(t *testing.T) {
	s := newLocalSigner(t)
	ctx := context.Background()
	stmt := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)

	envJSON, err := SignEnvelope(ctx, s, stmt)
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(envJSON, &env); err != nil {
		t.Fatal(err)
	}
	if env.PayloadType != InTotoPayloadType {
		t.Fatalf("payloadType = %q", env.PayloadType)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	if !bytes.Equal(payload, stmt) {
		t.Fatal("payload does not round-trip")
	}
	sig, _ := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	sum := sha256.Sum256(PAE(env.PayloadType, payload))
	if !ecdsa.VerifyASN1(&s.key.PublicKey, sum[:], sig) {
		t.Fatal("DSSE signature did not verify")
	}

	// Changing the payload must break the signature.
	bad := sha256.Sum256(PAE(env.PayloadType, []byte(`{"_type":"evil"}`)))
	if ecdsa.VerifyASN1(&s.key.PublicKey, bad[:], sig) {
		t.Fatal("DSSE signature verified a modified payload")
	}
}

func TestPAEMatchesSpecExample(t *testing.T) {
	// Example from the DSSE spec: payloadType "http://example.com/HelloWorld", payload "hello world".
	got := string(PAE("http://example.com/HelloWorld", []byte("hello world")))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if got != want {
		t.Fatalf("PAE = %q, want %q", got, want)
	}
}
