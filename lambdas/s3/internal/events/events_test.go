package events

import "testing"

const s3Event = `{
  "Records": [{
    "eventSource": "aws:s3",
    "eventName": "ObjectCreated:Put",
    "eventTime": "2026-11-22T15:00:00.000Z",
    "userIdentity": {"principalId": "AWS:AIDAEXAMPLE"},
    "requestParameters": {"sourceIPAddress": "203.0.113.7"},
    "s3": {
      "bucket": {"name": "group12-artifacts-111122223333"},
      "object": {"key": "builds/my+app+v1.exe", "size": 1024, "versionId": "abc"}
    }
  }]
}`

const ebEventJSON = `{
  "version": "0",
  "detail-type": "Object Created",
  "source": "aws.s3",
  "time": "2026-11-22T15:00:00Z",
  "detail": {
    "bucket": {"name": "group12-artifacts-111122223333"},
    "object": {"key": "builds/my app v1.exe", "size": 1024, "version-id": "abc"},
    "requester": "111122223333",
    "source-ip-address": "203.0.113.7"
  }
}`

const s3TestEvent = `{"Service":"Amazon S3","Event":"s3:TestEvent","Time":"2026-11-22T15:00:00.000Z","Bucket":"group12-artifacts-111122223333"}`

const s3DeleteEvent = `{"Records":[{"eventSource":"aws:s3","eventName":"ObjectRemoved:Delete","s3":{"bucket":{"name":"b"},"object":{"key":"k"}}}]}`

func TestParseS3NotificationDecodesKey(t *testing.T) {
	objs, err := Parse([]byte(s3Event))
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 1 {
		t.Fatalf("got %d objects, want 1", len(objs))
	}
	o := objs[0]
	if o.Key != "builds/my app v1.exe" {
		t.Errorf("key = %q, want spaces decoded", o.Key)
	}
	if o.Bucket != "group12-artifacts-111122223333" || o.Size != 1024 || o.Uploader != "AWS:AIDAEXAMPLE" || o.SourceIP != "203.0.113.7" {
		t.Errorf("unexpected object: %+v", o)
	}
}

func TestParseEventBridge(t *testing.T) {
	objs, err := Parse([]byte(ebEventJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 1 || objs[0].Key != "builds/my app v1.exe" || objs[0].VersionID != "abc" {
		t.Fatalf("unexpected: %+v", objs)
	}
}

func TestParseIgnoresS3TestEvent(t *testing.T) {
	objs, err := Parse([]byte(s3TestEvent))
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 0 {
		t.Fatalf("expected no objects, got %+v", objs)
	}
}

func TestParseIgnoresDeletes(t *testing.T) {
	objs, err := Parse([]byte(s3DeleteEvent))
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 0 {
		t.Fatalf("expected no objects, got %+v", objs)
	}
}

func TestParseRejectsUnknownEvent(t *testing.T) {
	if _, err := Parse([]byte(`{"hello":"world"}`)); err == nil {
		t.Fatal("expected an error for an unknown event shape")
	}
}
