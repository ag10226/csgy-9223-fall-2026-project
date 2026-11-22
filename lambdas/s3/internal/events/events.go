// Package events turns the JSON that starts the Lambda into a simple list of
// uploaded objects.
//
// Two event shapes are supported, so the code works no matter how Phillip
// routes events:
//   - a direct S3 notification  ({"Records":[{"s3":{...}}]})
//   - an EventBridge "Object Created" event ({"detail-type":"Object Created",...})
package events

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Object is one uploaded file the Lambda should sign.
type Object struct {
	Bucket    string
	Key       string
	VersionID string
	Size      int64
	Uploader  string
	SourceIP  string
	EventTime time.Time
}

// ---- direct S3 notification shape ----

type s3Notification struct {
	Records []s3Record `json:"Records"`
}

type s3Record struct {
	EventSource  string    `json:"eventSource"`
	EventName    string    `json:"eventName"`
	EventTime    time.Time `json:"eventTime"`
	UserIdentity struct {
		PrincipalID string `json:"principalId"`
	} `json:"userIdentity"`
	RequestParameters struct {
		SourceIPAddress string `json:"sourceIPAddress"`
	} `json:"requestParameters"`
	S3 struct {
		Bucket struct {
			Name string `json:"name"`
		} `json:"bucket"`
		Object struct {
			Key       string `json:"key"`
			Size      int64  `json:"size"`
			VersionID string `json:"versionId"`
		} `json:"object"`
	} `json:"s3"`
}

// ---- EventBridge shape ----

type eventBridgeEvent struct {
	DetailType string    `json:"detail-type"`
	Source     string    `json:"source"`
	Time       time.Time `json:"time"`
	Detail     struct {
		Bucket struct {
			Name string `json:"name"`
		} `json:"bucket"`
		Object struct {
			Key       string `json:"key"`
			Size      int64  `json:"size"`
			VersionID string `json:"version-id"`
		} `json:"object"`
		Requester string `json:"requester"`
		SourceIP  string `json:"source-ip-address"`
	} `json:"detail"`
}

// Parse reads the raw Lambda event and returns the objects to sign.
func Parse(raw []byte) ([]Object, error) {
	var probe struct {
		Records    json.RawMessage `json:"Records"`
		DetailType string          `json:"detail-type"`
		Event      string          `json:"Event"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("event is not valid JSON: %w", err)
	}

	switch {
	case probe.Event == "s3:TestEvent":
		return nil, nil // S3 sends this once when a notification is first set up
	case len(probe.Records) > 0:
		return parseS3(raw)
	case probe.DetailType != "":
		return parseEventBridge(raw)
	default:
		return nil, fmt.Errorf("unrecognised event: expected an S3 notification or an EventBridge S3 event")
	}
}

func parseS3(raw []byte) ([]Object, error) {
	var n s3Notification
	if err := json.Unmarshal(raw, &n); err != nil {
		return nil, fmt.Errorf("bad S3 notification: %w", err)
	}
	var out []Object
	for _, r := range n.Records {
		if r.EventSource != "aws:s3" || !strings.HasPrefix(r.EventName, "ObjectCreated:") {
			continue // not an upload (for example a delete event)
		}
		// S3 URL-encodes keys in notifications: "my file.exe" arrives as "my+file.exe".
		key, err := url.QueryUnescape(r.S3.Object.Key)
		if err != nil {
			return nil, fmt.Errorf("decoding object key %q: %w", r.S3.Object.Key, err)
		}
		out = append(out, Object{
			Bucket:    r.S3.Bucket.Name,
			Key:       key,
			VersionID: r.S3.Object.VersionID,
			Size:      r.S3.Object.Size,
			Uploader:  r.UserIdentity.PrincipalID,
			SourceIP:  r.RequestParameters.SourceIPAddress,
			EventTime: r.EventTime,
		})
	}
	return out, nil
}

func parseEventBridge(raw []byte) ([]Object, error) {
	var e eventBridgeEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("bad EventBridge event: %w", err)
	}
	if e.Source != "aws.s3" || e.DetailType != "Object Created" {
		return nil, nil // not an upload; nothing to do
	}
	// EventBridge keys are NOT URL-encoded, so use them as-is.
	return []Object{{
		Bucket:    e.Detail.Bucket.Name,
		Key:       e.Detail.Object.Key,
		VersionID: e.Detail.Object.VersionID,
		Size:      e.Detail.Object.Size,
		Uploader:  e.Detail.Requester,
		SourceIP:  e.Detail.SourceIP,
		EventTime: e.Time,
	}}, nil
}
