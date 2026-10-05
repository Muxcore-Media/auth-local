package internal

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Muxcore-Media/contracts-media/events"
)

type capturePublisher struct {
	eventType string
	source    string
	payload   []byte
}

func (c *capturePublisher) Publish(_ context.Context, eventType, source string, payload []byte) error {
	c.eventType = eventType
	c.source = source
	c.payload = append([]byte(nil), payload...)
	return nil
}

func TestPublishUserDeleted(t *testing.T) {
	pub := &capturePublisher{}
	if err := PublishUserDeleted(context.Background(), pub, "auth-local", "acct-9"); err != nil {
		t.Fatal(err)
	}
	if pub.eventType != events.EventIdentityUserDeleted || pub.source != "auth-local" {
		t.Fatalf("published %s from %s", pub.eventType, pub.source)
	}
	var body events.UserDeletedPayload
	if err := json.Unmarshal(pub.payload, &body); err != nil {
		t.Fatal(err)
	}
	if body.UserID != "acct-9" {
		t.Fatalf("payload %+v", body)
	}
	if err := PublishUserDeleted(context.Background(), nil, "auth-local", "acct-9"); err == nil {
		t.Fatal("expected missing publisher to fail")
	}
	if err := PublishUserDeleted(context.Background(), pub, "auth-local", " "); err == nil {
		t.Fatal("expected blank user id to fail")
	}
}
