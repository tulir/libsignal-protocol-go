package tests

import (
	"context"
	"fmt"
	"testing"

	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/logger"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/state/record"
)

// TestSerializing tests serialization and deserialization of Signal objects.
func TestSerializing(t *testing.T) {
	ctx := context.Background()

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	// Create a PreKeyBundle from Bob's prekey records and other
	// data.
	retrivedPreKey := prekey.NewBundle(
		bob.registrationID,
		bob.deviceID,
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
	)

	// Process Bob's retrieved prekey to establish a session.
	alice.sessionBuilder.ProcessBundle(ctx, retrivedPreKey)

	// Create a session cipher to encrypt messages to Bob.
	plaintextMessage := []byte("Hello!")
	sessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	sessionCipher.Encrypt(ctx, plaintextMessage)

	// Serialize our session so it can be stored.
	loadedSession, err := alice.sessionStore.LoadSession(ctx, bob.address)
	if err != nil {
		logger.Error("Failed to load session.")
		t.FailNow()
	}
	serializedSession := loadedSession.Serialize()
	logger.Debug(string(serializedSession))

	// Try deserializing our session back into an object.
	var deserializedSession *record.Session
	deserializedSession, err = record.NewSessionFromBytes(serializedSession, serializer.Session, serializer.State)
	if err != nil {
		logger.Error("Failed to deserialize session.")
		t.FailNow()
	}

	fmt.Printf("Original Session Record: %+v\n", loadedSession)
	fmt.Printf("Deserialized Session Record: %+v\n", deserializedSession)

}
