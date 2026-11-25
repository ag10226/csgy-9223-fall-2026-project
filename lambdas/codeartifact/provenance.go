package main

import (
	"fmt"
	"time"

	slsa "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	predicateTypeSLSAProvenanceV1 = "https://slsa.dev/provenance/v1"

	// buildTypeCodeArtifactPublish says what the attestation records: not a
	// build, but CodeArtifact publishing these exact bytes as this package
	// version, checked by this function. Same pattern as the S3 signer's
	// buildType: the team repo URL plus this Lambda's folder.
	buildTypeCodeArtifactPublish = "https://github.com/ag10226/csgy-9223-fall-2026-project/lambdas/codeartifact@v1"
)

// provenanceStatement describes a verified package version as an in-toto
// statement with a SLSA provenance v1 predicate. Every asset is a subject, so
// one signed attestation covers the whole package version.
//
// This function did not build the package: builder.id identifies the function
// attesting to what CodeArtifact published, not a build system.
func provenanceStatement(d packageVersionStateChange, v *verifiedVersion, builderID, invocationID string, finishedOn time.Time) (*intoto.Statement, error) {
	external, err := structpb.NewStruct(map[string]any{
		"domainOwner": d.DomainOwner,
		"domain":      d.DomainName,
		"repository":  d.RepositoryName,
		"format":      d.PackageFormat,
		"namespace":   d.PackageNamespace,
		"package":     d.PackageName,
		"version":     d.PackageVersion,
		"revision":    v.Revision,
	})
	if err != nil {
		return nil, err
	}
	internal, err := structpb.NewStruct(map[string]any{
		"originType":       v.OriginType,
		"originRepository": v.OriginRepository,
		"publishedTime":    v.PublishedTime.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, err
	}

	provenance := &slsa.Provenance{
		BuildDefinition: &slsa.BuildDefinition{
			BuildType:          buildTypeCodeArtifactPublish,
			ExternalParameters: external,
			InternalParameters: internal,
		},
		RunDetails: &slsa.RunDetails{
			Builder: &slsa.Builder{Id: builderID},
			Metadata: &slsa.BuildMetadata{
				InvocationId: invocationID,
				FinishedOn:   timestamppb.New(finishedOn),
			},
		},
	}
	if err := provenance.Validate(); err != nil {
		return nil, fmt.Errorf("invalid provenance: %w", err)
	}
	predicate, err := toStruct(provenance)
	if err != nil {
		return nil, err
	}

	statement := &intoto.Statement{
		Type:          intoto.StatementTypeUri,
		PredicateType: predicateTypeSLSAProvenanceV1,
		Predicate:     predicate,
	}
	for _, asset := range v.Assets {
		statement.Subject = append(statement.Subject, &intoto.ResourceDescriptor{
			Name:   asset.Name,
			Digest: map[string]string{"sha256": asset.SHA256},
		})
	}
	if err := statement.Validate(); err != nil {
		return nil, fmt.Errorf("invalid in-toto statement: %w", err)
	}
	return statement, nil
}

// toStruct converts a predicate message to the generic Struct an in-toto
// statement holds, keeping its JSON field names.
func toStruct(provenance *slsa.Provenance) (*structpb.Struct, error) {
	b, err := protojson.Marshal(provenance)
	if err != nil {
		return nil, err
	}
	s := &structpb.Struct{}
	if err := protojson.Unmarshal(b, s); err != nil {
		return nil, err
	}
	return s, nil
}
