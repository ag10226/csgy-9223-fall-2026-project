package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestStatementDescribesTheUpload(t *testing.T) {
	sum := sha256.Sum256([]byte("artifact"))
	up := UploadInfo{
		Bucket: "artifacts", Key: "builds/app.exe", Size: 8, VersionID: "v1",
		Uploader: "AWS:AIDAEXAMPLE", SourceIP: "203.0.113.7",
		EventTime: time.Date(2026, 11, 22, 15, 0, 0, 0, time.UTC),
	}
	run := RunInfo{
		SignerID:     "arn:aws:lambda:us-east-1:111122223333:function:group12-s3-signer",
		InvocationID: "req-1",
		StartedOn:    time.Date(2026, 11, 22, 15, 0, 1, 0, time.UTC),
	}

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
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			BuildDefinition struct {
				BuildType          string                 `json:"buildType"`
				ExternalParameters map[string]interface{} `json:"externalParameters"`
				InternalParameters map[string]interface{} `json:"internalParameters"`
			} `json:"buildDefinition"`
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
			} `json:"runDetails"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}

	if st.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("_type = %q", st.Type)
	}
	if st.PredicateType != SLSAProvenanceV1 {
		t.Errorf("predicateType = %q", st.PredicateType)
	}
	if len(st.Subject) != 1 || st.Subject[0].Name != "builds/app.exe" {
		t.Fatalf("subject = %+v", st.Subject)
	}
	if st.Subject[0].Digest["sha256"] != hex.EncodeToString(sum[:]) {
		t.Error("subject digest does not match the file")
	}
	ext := st.Predicate.BuildDefinition.ExternalParameters
	if ext["bucket"] != "artifacts" || ext["key"] != "builds/app.exe" || ext["versionId"] != "v1" {
		t.Errorf("externalParameters = %v", ext)
	}
	in := st.Predicate.BuildDefinition.InternalParameters
	if in["uploader"] != "AWS:AIDAEXAMPLE" || in["sourceIp"] != "203.0.113.7" || in["uploadedOn"] != "2026-11-22T15:00:00Z" {
		t.Errorf("internalParameters = %v", in)
	}
	if st.Predicate.RunDetails.Builder.ID != run.SignerID {
		t.Errorf("builder id = %q", st.Predicate.RunDetails.Builder.ID)
	}
}

func TestOptionalFieldsAreOmitted(t *testing.T) {
	sum := sha256.Sum256(nil)
	raw, err := BuildStatement(sum[:], UploadInfo{Bucket: "b", Key: "k"}, RunInfo{StartedOn: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]interface{}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	bd := st["predicate"].(map[string]interface{})["buildDefinition"].(map[string]interface{})
	if _, ok := bd["externalParameters"].(map[string]interface{})["versionId"]; ok {
		t.Error("versionId should be omitted when empty")
	}
	if len(bd["internalParameters"].(map[string]interface{})) != 0 {
		t.Error("internalParameters should be empty when nothing is known")
	}
}
