package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Muxcore-Media/contracts-media/events"
)

// UserDeletedEvent is the identity.user.deleted type and JSON payload.
func UserDeletedEvent(userID string) (eventType string, payload []byte, err error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return "", nil, fmt.Errorf("user_id is required")
	}
	raw, err := json.Marshal(events.UserDeletedPayload{UserID: userID})
	if err != nil {
		return "", nil, err
	}
	return events.EventIdentityUserDeleted, raw, nil
}

// EventPublisher publishes one core event.
type EventPublisher interface {
	Publish(ctx context.Context, eventType, source string, payload []byte) error
}

// PublishUserDeleted sends identity.user.deleted. A nil publisher is an error
// so the caller can log a missed fan-out; the auth row is already gone.
func PublishUserDeleted(ctx context.Context, pub EventPublisher, source, userID string) error {
	if pub == nil {
		return fmt.Errorf("core events client not connected")
	}
	eventType, payload, err := UserDeletedEvent(userID)
	if err != nil {
		return err
	}
	return pub.Publish(ctx, eventType, source, payload)
}
