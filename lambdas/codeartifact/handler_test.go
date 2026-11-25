package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go-v2/service/codeartifact"
	catypes "github.com/aws/aws-sdk-go-v2/service/codeartifact/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

// Values from testdata/published-generic.json, captured from the sandbox.
const (
	testRevision    = "pSRdC7y1JXc4BEcB/urBQC1gaXQiXk0ouNh31pY+t0E="
	testPrefix      = "codeartifact/group12-dan-sandbox/packages/generic/group12/hello/0.1.1795367349/pSRdC7y1JXc4BEcB_urBQC1gaXQiXk0ouNh31pY-t0E"
	testFunctionARN = "arn:aws:lambda:us-east-1:111122223333:function:codeartifact-signer"
)

// A cosign key pair stands in for the KMS key: cosign signs with it through the
// same code path it uses for awskms:// keys. Generated once for all tests.
var testKeyRef, testPublicKey string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "codeartifact-signer-test-")
	if err != nil {
		panic(err)
	}
	keys, err := cosign.GenerateKeyPair(func(bool) ([]byte, error) { return nil, nil })
	if err != nil {
		panic(err)
	}
	testKeyRef = filepath.Join(dir, "cosign.key")
	testPublicKey = filepath.Join(dir, "cosign.pub")
	if err := os.WriteFile(testKeyRef, keys.PrivateBytes, 0o600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(testPublicKey, keys.PublicBytes, 0o600); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type fakeCodeArtifact struct {
	status   catypes.PackageVersionStatus
	origin   *catypes.PackageVersionOrigin
	revision string
	assets   map[string][]byte // asset name -> content
	reported map[string]string // asset name -> SHA-256 CodeArtifact reports, when it should differ from the content
	fetched  []string
}

func newFakeCodeArtifact(assets map[string][]byte) *fakeCodeArtifact {
	return &fakeCodeArtifact{
		status:   catypes.PackageVersionStatusPublished,
		origin:   &catypes.PackageVersionOrigin{OriginType: catypes.PackageVersionOriginTypeInternal},
		revision: testRevision,
		assets:   assets,
	}
}

func (f *fakeCodeArtifact) DescribePackageVersion(_ context.Context, _ *codeartifact.DescribePackageVersionInput, _ ...func(*codeartifact.Options)) (*codeartifact.DescribePackageVersionOutput, error) {
	return &codeartifact.DescribePackageVersionOutput{
		PackageVersion: &catypes.PackageVersionDescription{Status: f.status, Origin: f.origin, Revision: &f.revision},
	}, nil
}

func (f *fakeCodeArtifact) ListPackageVersionAssets(_ context.Context, _ *codeartifact.ListPackageVersionAssetsInput, _ ...func(*codeartifact.Options)) (*codeartifact.ListPackageVersionAssetsOutput, error) {
	names := make([]string, 0, len(f.assets))
	for name := range f.assets {
		names = append(names, name)
	}
	sort.Strings(names)

	out := &codeartifact.ListPackageVersionAssetsOutput{VersionRevision: &f.revision}
	for _, name := range names {
		content := f.assets[name]
		hash, ok := f.reported[name]
		if !ok {
			hash = sha256Hex(content)
		}
		size := int64(len(content))
		out.Assets = append(out.Assets, catypes.AssetSummary{
			Name:   &name,
			Size:   &size,
			Hashes: map[string]string{string(catypes.HashAlgorithmSha256): hash},
		})
	}
	return out, nil
}

func (f *fakeCodeArtifact) GetPackageVersionAsset(_ context.Context, in *codeartifact.GetPackageVersionAssetInput, _ ...func(*codeartifact.Options)) (*codeartifact.GetPackageVersionAssetOutput, error) {
	f.fetched = append(f.fetched, *in.Asset)
	return &codeartifact.GetPackageVersionAssetOutput{
		Asset:                  io.NopCloser(bytes.NewReader(f.assets[*in.Asset])),
		AssetName:              in.Asset,
		PackageVersionRevision: in.PackageVersionRevision,
	}, nil
}

type fakeS3 struct {
	objects map[string][]byte
	puts    []string // keys written, in order
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string][]byte{}}
}

func (f *fakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if _, ok := f.objects[*in.Key]; ok {
		return &s3.HeadObjectOutput{}, nil
	}
	return nil, &s3types.NotFound{}
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if _, ok := f.objects[*in.Key]; ok && in.IfNoneMatch != nil && *in.IfNoneMatch == "*" {
		return nil, &smithy.GenericAPIError{Code: "PreconditionFailed"}
	}
	body, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	f.objects[*in.Key] = body
	f.puts = append(f.puts, *in.Key)
	return &s3.PutObjectOutput{}, nil
}

func newTestHandler(t *testing.T, ca *fakeCodeArtifact, s3 *fakeS3) *Handler {
	t.Helper()
	return &Handler{
		codeArtifact: ca,
		s3:           s3,
		keyRef:       testKeyRef,
		bucket:       "test-bucket",
		prefix:       "codeartifact",
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func lambdaContext() context.Context {
	return lambdacontext.NewContext(context.Background(), &lambdacontext.LambdaContext{
		AwsRequestID:       "request-1",
		InvokedFunctionArn: testFunctionARN,
	})
}

func loadEvent(t *testing.T, name string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func loadDetail(t *testing.T, name string) packageVersionStateChange {
	t.Helper()
	var event events.EventBridgeEvent
	if err := json.Unmarshal(loadEvent(t, name), &event); err != nil {
		t.Fatal(err)
	}
	var detail packageVersionStateChange
	if err := json.Unmarshal(event.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	return detail
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writeBundleAndFile saves a bundle and the file it covers for cosign to read.
func writeBundleAndFile(t *testing.T, bundle, content []byte) (bundlePath, filePath string) {
	t.Helper()
	dir := t.TempDir()
	bundlePath = filepath.Join(dir, "bundle.json")
	filePath = filepath.Join(dir, "file")
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return bundlePath, filePath
}

// cosignVerifyBlob runs the check a consumer runs:
//
//	cosign verify-blob --key cosign.pub --bundle <bundle> --insecure-ignore-tlog=true <file>
func cosignVerifyBlob(t *testing.T, bundle, content []byte) error {
	t.Helper()
	bundlePath, filePath := writeBundleAndFile(t, bundle, content)
	cmd := verify.VerifyBlobCmd{
		KeyOpts:    options.KeyOpts{KeyRef: testPublicKey, BundlePath: bundlePath, NewBundleFormat: true},
		IgnoreTlog: true,
	}
	return cmd.Exec(context.Background(), filePath)
}

// cosignVerifyAttestation runs the check a consumer runs:
//
//	cosign verify-blob-attestation --key cosign.pub --bundle <bundle> \
//	  --type slsaprovenance1 --insecure-ignore-tlog=true <file>
func cosignVerifyAttestation(t *testing.T, bundle, content []byte) error {
	t.Helper()
	bundlePath, filePath := writeBundleAndFile(t, bundle, content)
	cmd := verify.VerifyBlobAttestationCommand{
		KeyOpts:       options.KeyOpts{KeyRef: testPublicKey, BundlePath: bundlePath, NewBundleFormat: true},
		IgnoreTlog:    true,
		PredicateType: "slsaprovenance1",
		CheckClaims:   true,
	}
	return cmd.Exec(context.Background(), filePath)
}

// attestedStatement returns the in-toto statement inside an attestation bundle.
func attestedStatement(t *testing.T, bundle []byte) map[string]any {
	t.Helper()
	var b struct {
		DsseEnvelope struct {
			Payload []byte `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil {
		t.Fatal(err)
	}
	var statement map[string]any
	if err := json.Unmarshal(b.DsseEnvelope.Payload, &statement); err != nil {
		t.Fatal(err)
	}
	return statement
}

func TestSkipEventReason(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*packageVersionStateChange)
		skip   bool
	}{
		{name: "published", modify: func(*packageVersionStateChange) {}},
		{name: "unfinished", modify: func(d *packageVersionStateChange) { d.PackageVersionState = "Unfinished" }, skip: true},
		{name: "unlisted", modify: func(d *packageVersionStateChange) { d.PackageVersionState = "Unlisted" }, skip: true},
		{name: "deleted", modify: func(d *packageVersionStateChange) { d.OperationType = "Deleted" }, skip: true},
		{
			name: "metadata only",
			modify: func(d *packageVersionStateChange) {
				d.OperationType = "Updated"
				d.Changes.AssetsAdded = 0
				d.Changes.StatusChanged = false
			},
			skip: true,
		},
		{
			name: "asset added to published version",
			modify: func(d *packageVersionStateChange) {
				d.OperationType = "Updated"
				d.Changes.StatusChanged = false
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := loadDetail(t, "published-generic.json")
			tt.modify(&d)
			if reason := skipEventReason(d); (reason != "") != tt.skip {
				t.Errorf("skipEventReason() = %q, want skip=%v", reason, tt.skip)
			}
		})
	}
}

func TestHandleSignsPublishedVersion(t *testing.T) {
	assets := map[string][]byte{
		"hello.tgz":  []byte("hello from group12"),
		"README.txt": []byte("read me"),
	}
	ca := newFakeCodeArtifact(assets)
	s := newFakeS3()
	h := newTestHandler(t, ca, s)

	if err := h.Handle(lambdaContext(), loadEvent(t, "published-generic.json")); err != nil {
		t.Fatalf("Handle() = %v", err)
	}

	provenanceKey := testPrefix + "/provenance.att.sigstore.json"
	wantPuts := []string{
		testPrefix + "/assets/README.txt.sigstore.json",
		testPrefix + "/assets/hello.tgz.sigstore.json",
		provenanceKey, // last: marks the revision as signed
	}
	if strings.Join(s.puts, "\n") != strings.Join(wantPuts, "\n") {
		t.Fatalf("wrote %v, want %v", s.puts, wantPuts)
	}

	provenance := s.objects[provenanceKey]
	for name, content := range assets {
		signature := s.objects[testPrefix+"/assets/"+name+".sigstore.json"]
		if err := cosignVerifyBlob(t, signature, content); err != nil {
			t.Errorf("signature for %s does not verify: %v", name, err)
		}
		if err := cosignVerifyAttestation(t, provenance, content); err != nil {
			t.Errorf("provenance does not verify for %s: %v", name, err)
		}

		tampered := append(bytes.Clone(content), 'x')
		if err := cosignVerifyBlob(t, signature, tampered); err == nil {
			t.Errorf("signature for %s verified a tampered copy", name)
		}
		if err := cosignVerifyAttestation(t, provenance, tampered); err == nil {
			t.Errorf("provenance verified a tampered copy of %s", name)
		}
	}

	statement := attestedStatement(t, provenance)
	if statement["predicateType"] != predicateTypeSLSAProvenanceV1 {
		t.Errorf("predicate type = %v", statement["predicateType"])
	}
	if subjects := statement["subject"].([]any); len(subjects) != len(assets) {
		t.Errorf("attestation has %d subjects, want %d", len(subjects), len(assets))
	}
	predicate := statement["predicate"].(map[string]any)
	buildDefinition := predicate["buildDefinition"].(map[string]any)
	if buildDefinition["buildType"] != buildTypeCodeArtifactPublish {
		t.Errorf("buildType = %v", buildDefinition["buildType"])
	}
	builder := predicate["runDetails"].(map[string]any)["builder"].(map[string]any)["id"]
	if builder != testFunctionARN {
		t.Errorf("builder.id = %v, want %s", builder, testFunctionARN)
	}
	params := buildDefinition["externalParameters"].(map[string]any)
	if params["package"] != "hello" || params["version"] != "0.1.1795367349" || params["revision"] != testRevision {
		t.Errorf("externalParameters = %v", params)
	}
}

func TestHandleSigningFailureWritesNothing(t *testing.T) {
	ca := newFakeCodeArtifact(map[string][]byte{"hello.tgz": []byte("hello")})
	s := newFakeS3()
	h := newTestHandler(t, ca, s)
	h.keyRef = filepath.Join(t.TempDir(), "missing.key")

	if err := h.Handle(lambdaContext(), loadEvent(t, "published-generic.json")); err == nil {
		t.Fatal("Handle() succeeded without a usable key")
	}
	if len(s.puts) > 0 {
		t.Errorf("wrote %v, want nothing when signing fails", s.puts)
	}
}

func TestHandleKeepsExistingSignatures(t *testing.T) {
	// An earlier attempt signed the asset but failed before the attestation.
	ca := newFakeCodeArtifact(map[string][]byte{"hello.tgz": []byte("hello")})
	s := newFakeS3()
	assetKey := testPrefix + "/assets/hello.tgz.sigstore.json"
	s.objects[assetKey] = []byte("earlier signature")
	h := newTestHandler(t, ca, s)

	if err := h.Handle(lambdaContext(), loadEvent(t, "published-generic.json")); err != nil {
		t.Fatalf("Handle() = %v", err)
	}
	if got := string(s.objects[assetKey]); got != "earlier signature" {
		t.Errorf("existing asset signature was overwritten")
	}
	if _, ok := s.objects[testPrefix+"/provenance.att.sigstore.json"]; !ok {
		t.Errorf("provenance was not written")
	}
}

func TestHandleRequiresLambdaContext(t *testing.T) {
	ca := newFakeCodeArtifact(map[string][]byte{"hello.tgz": []byte("hello")})
	h := newTestHandler(t, ca, newFakeS3())
	if err := h.Handle(context.Background(), loadEvent(t, "published-generic.json")); err == nil {
		t.Error("Handle() succeeded without a Lambda context")
	}
}

func TestVerifyPublishedInternal(t *testing.T) {
	content := []byte("hello from group12")
	ca := newFakeCodeArtifact(map[string][]byte{"hello.tgz": content})
	h := newTestHandler(t, ca, newFakeS3())

	dir := t.TempDir()
	verified, reason, err := h.verify(context.Background(), h.logger, loadDetail(t, "published-generic.json"), dir)
	if err != nil || reason != "" {
		t.Fatalf("verify() reason=%q err=%v, want success", reason, err)
	}
	if verified.Revision != testRevision {
		t.Errorf("revision = %q, want %q", verified.Revision, testRevision)
	}
	want := verifiedAsset{Name: "hello.tgz", Size: int64(len(content)), SHA256: sha256Hex(content), Path: filepath.Join(dir, "asset-0")}
	if len(verified.Assets) != 1 || verified.Assets[0] != want {
		t.Fatalf("assets = %+v, want %+v", verified.Assets, want)
	}
	if saved, err := os.ReadFile(want.Path); err != nil || !bytes.Equal(saved, content) {
		t.Errorf("saved copy = %q, %v; want %q", saved, err, content)
	}
}

func TestVerifySkips(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*fakeCodeArtifact, *fakeS3)
		reason string
	}{
		{
			name:   "no longer published",
			modify: func(ca *fakeCodeArtifact, _ *fakeS3) { ca.status = catypes.PackageVersionStatusArchived },
			reason: "now Archived",
		},
		{
			name: "external origin",
			modify: func(ca *fakeCodeArtifact, _ *fakeS3) {
				ca.origin = &catypes.PackageVersionOrigin{OriginType: catypes.PackageVersionOriginTypeExternal}
			},
			reason: "EXTERNAL",
		},
		{
			name:   "origin missing",
			modify: func(ca *fakeCodeArtifact, _ *fakeS3) { ca.origin = nil },
			reason: "UNKNOWN",
		},
		{
			name:   "already signed",
			modify: func(_ *fakeCodeArtifact, s *fakeS3) { s.objects[testPrefix+"/"+provenanceObject] = nil },
			reason: "already signed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newFakeCodeArtifact(map[string][]byte{"hello.tgz": []byte("hello")})
			s := newFakeS3()
			tt.modify(ca, s)
			h := newTestHandler(t, ca, s)

			verified, reason, err := h.verify(context.Background(), h.logger, loadDetail(t, "published-generic.json"), t.TempDir())
			if err != nil || verified != nil || !strings.Contains(reason, tt.reason) {
				t.Errorf("verify() = %v, %q, %v; want skip reason containing %q", verified, reason, err, tt.reason)
			}
			if len(ca.fetched) > 0 {
				t.Errorf("downloaded %v, want no downloads when skipping", ca.fetched)
			}
		})
	}
}

func TestVerifyHashMismatch(t *testing.T) {
	ca := newFakeCodeArtifact(map[string][]byte{"hello.tgz": []byte("tampered")})
	ca.reported = map[string]string{"hello.tgz": sha256Hex([]byte("original"))}
	h := newTestHandler(t, ca, newFakeS3())

	_, _, err := h.verify(context.Background(), h.logger, loadDetail(t, "published-generic.json"), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Errorf("verify() err = %v, want integrity check failure", err)
	}
}

func TestHandleIgnoresOtherEvents(t *testing.T) {
	ca := newFakeCodeArtifact(nil)
	h := newTestHandler(t, ca, newFakeS3())
	event := `{"source":"aws.s3","detail-type":"Object Created","detail":{}}`
	if err := h.Handle(lambdaContext(), json.RawMessage(event)); err != nil {
		t.Fatalf("Handle() = %v", err)
	}
	if len(ca.fetched) > 0 {
		t.Errorf("downloaded %v for a non-CodeArtifact event", ca.fetched)
	}
}

func TestVersionPrefix(t *testing.T) {
	d := loadDetail(t, "published-generic.json")
	if got := versionPrefix("codeartifact", d, testRevision); got != testPrefix {
		t.Errorf("versionPrefix() = %q, want %q", got, testPrefix)
	}

	d.PackageNamespace = ""
	d.PackageVersion = "1.0.0+build/7"
	want := "codeartifact/group12-dan-sandbox/packages/generic/_/hello/1.0.0+build%2F7/rev"
	if got := versionPrefix("codeartifact", d, "rev"); got != want {
		t.Errorf("versionPrefix() = %q, want %q", got, want)
	}
}
