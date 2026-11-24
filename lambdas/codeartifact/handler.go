package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codeartifact"
	catypes "github.com/aws/aws-sdk-go-v2/service/codeartifact/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"group12/lambdas/codeartifact/internal/signing"
)

const (
	eventSource                         = "aws.codeartifact"
	detailTypePackageVersionStateChange = "CodeArtifact Package Version State Change"

	// provenanceObject is written last for each revision, so its presence
	// means the revision has been fully signed.
	provenanceObject = "provenance.sigstore.json"
)

// packageVersionStateChange is the detail of a "CodeArtifact Package Version
// State Change" event. See testdata/ for real examples and
// https://docs.aws.amazon.com/codeartifact/latest/ug/monitoring-events.html
type packageVersionStateChange struct {
	DomainOwner            string `json:"domainOwner"`
	DomainName             string `json:"domainName"`
	RepositoryName         string `json:"repositoryName"`
	PackageFormat          string `json:"packageFormat"`
	PackageNamespace       string `json:"packageNamespace"`
	PackageName            string `json:"packageName"`
	PackageVersion         string `json:"packageVersion"`
	PackageVersionState    string `json:"packageVersionState"`
	PackageVersionRevision string `json:"packageVersionRevision"`
	Changes                struct {
		AssetsAdded     int  `json:"assetsAdded"`
		AssetsRemoved   int  `json:"assetsRemoved"`
		AssetsUpdated   int  `json:"assetsUpdated"`
		MetadataUpdated bool `json:"metadataUpdated"`
		StatusChanged   bool `json:"statusChanged"`
	} `json:"changes"`
	OperationType  string `json:"operationType"`
	SequenceNumber int64  `json:"sequenceNumber"`
}

// verifiedAsset is a package file whose downloaded bytes matched the SHA-256
// and size CodeArtifact reports for it.
type verifiedAsset struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// verifiedVersion is a package version ready to be signed.
type verifiedVersion struct {
	Revision         string
	Assets           []verifiedAsset
	OriginType       string
	OriginRepository string
	PublishedTime    time.Time
}

type codeArtifactAPI interface {
	DescribePackageVersion(context.Context, *codeartifact.DescribePackageVersionInput, ...func(*codeartifact.Options)) (*codeartifact.DescribePackageVersionOutput, error)
	ListPackageVersionAssets(context.Context, *codeartifact.ListPackageVersionAssetsInput, ...func(*codeartifact.Options)) (*codeartifact.ListPackageVersionAssetsOutput, error)
	GetPackageVersionAsset(context.Context, *codeartifact.GetPackageVersionAssetInput, ...func(*codeartifact.Options)) (*codeartifact.GetPackageVersionAssetOutput, error)
}

type s3API interface {
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type Handler struct {
	codeArtifact codeArtifactAPI
	s3           s3API
	signer       *signing.Signer
	bucket       string
	prefix       string
	logger       *slog.Logger
}

func (h *Handler) Handle(ctx context.Context, raw json.RawMessage) error {
	// Log the event exactly as received so it can be copied into testdata/.
	h.logger.InfoContext(ctx, "received event", "event", raw)

	var event events.EventBridgeEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return fmt.Errorf("parse event: %w", err)
	}
	if event.Source != eventSource || event.DetailType != detailTypePackageVersionStateChange {
		h.logger.WarnContext(ctx, "ignoring unexpected event", "source", event.Source, "detailType", event.DetailType)
		return nil
	}

	var detail packageVersionStateChange
	if err := json.Unmarshal(event.Detail, &detail); err != nil {
		return fmt.Errorf("parse event detail: %w", err)
	}
	logger := h.logger.With(
		"domain", detail.DomainName,
		"repository", detail.RepositoryName,
		"format", detail.PackageFormat,
		"namespace", detail.PackageNamespace,
		"package", detail.PackageName,
		"version", detail.PackageVersion,
	)

	if reason := skipEventReason(detail); reason != "" {
		logger.InfoContext(ctx, "skipping event", "reason", reason, "state", detail.PackageVersionState, "operation", detail.OperationType)
		return nil
	}

	// The attestation names this function as the attester.
	lc, ok := lambdacontext.FromContext(ctx)
	if !ok {
		return errors.New("no Lambda context: cannot identify the attesting function")
	}

	verified, reason, err := h.verify(ctx, logger, detail)
	if err != nil {
		return err
	}
	if reason != "" {
		logger.InfoContext(ctx, "skipping package version", "reason", reason)
		return nil
	}

	prefix, err := h.sign(ctx, detail, verified, lc.InvokedFunctionArn, lc.AwsRequestID)
	if err != nil {
		return err
	}
	logger.InfoContext(ctx, "signed package version",
		"revision", verified.Revision,
		"assets", verified.Assets,
		"location", fmt.Sprintf("s3://%s/%s/", h.bucket, prefix),
	)
	return nil
}

// sign writes a signature bundle for every asset, then the provenance
// attestation. The attestation goes last because its presence marks the
// revision as fully signed. It returns the S3 prefix written to.
func (h *Handler) sign(ctx context.Context, d packageVersionStateChange, v *verifiedVersion, builderID, invocationID string) (string, error) {
	prefix := versionPrefix(h.prefix, d, v.Revision)
	for _, asset := range v.Assets {
		digest, err := hex.DecodeString(asset.SHA256)
		if err != nil {
			return "", fmt.Errorf("decode digest of asset %s: %w", asset.Name, err)
		}
		bundle, err := h.signer.SignBlob(ctx, digest)
		if err != nil {
			return "", fmt.Errorf("sign asset %s: %w", asset.Name, err)
		}
		if err := h.putOnce(ctx, assetSignatureKey(prefix, asset.Name), bundle); err != nil {
			return "", err
		}
	}

	statement, err := provenanceStatement(d, v, builderID, invocationID, time.Now())
	if err != nil {
		return "", err
	}
	bundle, err := h.signer.SignStatement(ctx, statement)
	if err != nil {
		return "", fmt.Errorf("sign provenance: %w", err)
	}
	if err := h.putOnce(ctx, provenanceKey(prefix), bundle); err != nil {
		return "", err
	}
	return prefix, nil
}

// putOnce writes an object only if its key doesn't exist yet, so a signature
// is never overwritten. An existing object came from an earlier or concurrent
// attempt at the same revision, which signed the same digests, so it is kept.
func (h *Handler) putOnce(ctx context.Context, key string, body []byte) error {
	_, err := h.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &h.bucket,
		Key:         &key,
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
		IfNoneMatch: aws.String("*"),
	})
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "PreconditionFailed" {
		h.logger.InfoContext(ctx, "keeping existing object", "key", key)
		return nil
	}
	if err != nil {
		return fmt.Errorf("write s3://%s/%s: %w", h.bucket, key, err)
	}
	return nil
}

// skipEventReason decides from the event alone whether it can be ignored.
// It returns "" when the package version should be processed.
func skipEventReason(d packageVersionStateChange) string {
	switch {
	case d.OperationType == "Deleted":
		return "package version was deleted"
	case d.PackageVersionState != string(catypes.PackageVersionStatusPublished):
		return "package version is not Published"
	case !d.Changes.StatusChanged && d.Changes.AssetsAdded == 0 && d.Changes.AssetsUpdated == 0 && d.Changes.AssetsRemoved == 0:
		return "only metadata changed"
	}
	return ""
}

// verify downloads every asset of the package version and checks it against
// the hashes CodeArtifact reports. The event is only a trigger: status, origin,
// and assets are re-read from the CodeArtifact API, since anyone allowed to
// invoke the function could send it a crafted event.
//
// It returns a non-empty reason when the version should not be signed.
func (h *Handler) verify(ctx context.Context, logger *slog.Logger, d packageVersionStateChange) (*verifiedVersion, string, error) {
	desc, err := h.codeArtifact.DescribePackageVersion(ctx, &codeartifact.DescribePackageVersionInput{
		Domain:         &d.DomainName,
		DomainOwner:    &d.DomainOwner,
		Repository:     &d.RepositoryName,
		Format:         catypes.PackageFormat(d.PackageFormat),
		Namespace:      optional(d.PackageNamespace),
		Package:        &d.PackageName,
		PackageVersion: &d.PackageVersion,
	})
	if err != nil {
		return nil, "", fmt.Errorf("describe package version: %w", err)
	}
	if status := desc.PackageVersion.Status; status != catypes.PackageVersionStatusPublished {
		return nil, fmt.Sprintf("package version is now %s", status), nil
	}
	// Only sign what was published into the domain. Versions pulled in from an
	// external connection (e.g. npmjs.com) were not published by us.
	origin := catypes.PackageVersionOriginTypeUnknown
	var originRepository string
	if o := desc.PackageVersion.Origin; o != nil {
		origin = o.OriginType
		if o.DomainEntryPoint != nil {
			originRepository = deref(o.DomainEntryPoint.RepositoryName)
		}
	}
	if origin != catypes.PackageVersionOriginTypeInternal {
		return nil, fmt.Sprintf("origin is %s, not INTERNAL", origin), nil
	}

	assets, revision, err := h.listAssets(ctx, d)
	if err != nil {
		return nil, "", err
	}
	if revision != d.PackageVersionRevision {
		// A newer revision exists. Sign that one; its own event will then
		// find it already signed.
		logger.InfoContext(ctx, "revision changed since event", "eventRevision", d.PackageVersionRevision, "currentRevision", revision)
	}

	signed, err := h.alreadySigned(ctx, d, revision)
	if err != nil {
		return nil, "", err
	}
	if signed {
		return nil, "revision is already signed", nil
	}

	verified := &verifiedVersion{
		Revision:         revision,
		OriginType:       string(origin),
		OriginRepository: originRepository,
	}
	if desc.PackageVersion.PublishedTime != nil {
		verified.PublishedTime = *desc.PackageVersion.PublishedTime
	}
	for _, asset := range assets {
		va, err := h.fetchAndVerify(ctx, d, revision, asset)
		if err != nil {
			return nil, "", err
		}
		verified.Assets = append(verified.Assets, va)
	}
	return verified, "", nil
}

func (h *Handler) listAssets(ctx context.Context, d packageVersionStateChange) ([]catypes.AssetSummary, string, error) {
	pages := codeartifact.NewListPackageVersionAssetsPaginator(h.codeArtifact, &codeartifact.ListPackageVersionAssetsInput{
		Domain:         &d.DomainName,
		DomainOwner:    &d.DomainOwner,
		Repository:     &d.RepositoryName,
		Format:         catypes.PackageFormat(d.PackageFormat),
		Namespace:      optional(d.PackageNamespace),
		Package:        &d.PackageName,
		PackageVersion: &d.PackageVersion,
	})
	var assets []catypes.AssetSummary
	var revision string
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("list package version assets: %w", err)
		}
		pageRevision := deref(page.VersionRevision)
		if revision != "" && pageRevision != revision {
			return nil, "", fmt.Errorf("revision changed while listing assets (%s, then %s)", revision, pageRevision)
		}
		revision = pageRevision
		assets = append(assets, page.Assets...)
	}
	if len(assets) == 0 {
		return nil, "", errors.New("package version has no assets")
	}
	return assets, revision, nil
}

func (h *Handler) alreadySigned(ctx context.Context, d packageVersionStateChange, revision string) (bool, error) {
	key := provenanceKey(versionPrefix(h.prefix, d, revision))
	_, err := h.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &h.bucket, Key: &key})
	if err == nil {
		return true, nil
	}
	var notFound *s3types.NotFound
	if errors.As(err, &notFound) {
		return false, nil
	}
	return false, fmt.Errorf("check s3://%s/%s: %w", h.bucket, key, err)
}

// fetchAndVerify streams one asset from CodeArtifact, hashing it as it goes,
// and fails if the bytes don't match the SHA-256 and size CodeArtifact reports.
func (h *Handler) fetchAndVerify(ctx context.Context, d packageVersionStateChange, revision string, asset catypes.AssetSummary) (verifiedAsset, error) {
	name := deref(asset.Name)
	want := asset.Hashes[string(catypes.HashAlgorithmSha256)]
	if want == "" {
		return verifiedAsset{}, fmt.Errorf("asset %s: CodeArtifact reported no SHA-256", name)
	}

	out, err := h.codeArtifact.GetPackageVersionAsset(ctx, &codeartifact.GetPackageVersionAssetInput{
		Domain:                 &d.DomainName,
		DomainOwner:            &d.DomainOwner,
		Repository:             &d.RepositoryName,
		Format:                 catypes.PackageFormat(d.PackageFormat),
		Namespace:              optional(d.PackageNamespace),
		Package:                &d.PackageName,
		PackageVersion:         &d.PackageVersion,
		PackageVersionRevision: &revision,
		Asset:                  &name,
	})
	if err != nil {
		return verifiedAsset{}, fmt.Errorf("get asset %s: %w", name, err)
	}
	defer out.Asset.Close()

	hash := sha256.New()
	size, err := io.Copy(hash, out.Asset)
	if err != nil {
		return verifiedAsset{}, fmt.Errorf("download asset %s: %w", name, err)
	}
	got := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(got, want) {
		return verifiedAsset{}, fmt.Errorf("integrity check failed for asset %s: CodeArtifact reports sha256 %s, downloaded bytes hash to %s", name, want, got)
	}
	if asset.Size != nil && size != *asset.Size {
		return verifiedAsset{}, fmt.Errorf("integrity check failed for asset %s: CodeArtifact reports %d bytes, downloaded %d", name, *asset.Size, size)
	}
	return verifiedAsset{Name: name, Size: size, SHA256: got}, nil
}

// versionPrefix is the S3 key prefix holding one revision's signatures and
// attestation:
//
//	<prefix>/<domain>/<repo>/<format>/<namespace>/<package>/<version>/<revision>/
//	    assets/<asset>.sigstore.json   signature over each asset
//	    provenance.sigstore.json        attestation covering all assets
//
// Asset signatures sit in their own folder so no asset name (for example a
// generic package asset named "provenance") can collide with the attestation.
// An empty namespace becomes "_". The revision is base64, so it is rewritten
// to the URL-safe alphabet to keep "/" out of the key.
func versionPrefix(prefix string, d packageVersionStateChange, revision string) string {
	namespace := d.PackageNamespace
	if namespace == "" {
		namespace = "_"
	}
	urlSafeRevision := strings.NewReplacer("/", "_", "+", "-").Replace(strings.TrimRight(revision, "="))
	segments := []string{d.DomainName, d.RepositoryName, d.PackageFormat, namespace, d.PackageName, d.PackageVersion, urlSafeRevision}
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return prefix + "/" + strings.Join(segments, "/")
}

func assetSignatureKey(versionPrefix, assetName string) string {
	return versionPrefix + "/assets/" + url.PathEscape(assetName) + ".sigstore.json"
}

func provenanceKey(versionPrefix string) string {
	return versionPrefix + "/" + provenanceObject
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
