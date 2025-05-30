package tests

import (
	"context"
	"testing"

	"go.mau.fi/libsignal/keys/message"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/logger"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/session"
)

// TestSavedMessageKeys tests the ability to save message keys for use in
// decrypting messages in the future.
func TestSavedMessageKeys(t *testing.T) {
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
	logger.Debug("Fetching Bob's prekey with ID: ", bob.preKeys[0].ID())
	retrievedPreKey := prekey.NewBundle(
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
	logger.Debug("Building sender's (Alice) session...")
	err := alice.sessionBuilder.ProcessBundle(ctx, retrievedPreKey)
	if err != nil {
		logger.Error("Unable to process retrieved prekey bundle")
		t.FailNow()
	}

	// Create a session cipher to encrypt messages to Bob.
	plaintextMessage := []byte("Hello!")
	logger.Info("Plaintext message: ", string(plaintextMessage))
	sessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	message, err := sessionCipher.Encrypt(ctx, plaintextMessage)
	if err != nil {
		logger.Error("Unable to encrypt message: ", err)
		t.FailNow()
	}

	logger.Info("Encrypted message: ", message)

	///////////// RECEIVER SESSION CREATION ///////////////

	// Emulate receiving the message as JSON over the network.
	logger.Debug("Building message from bytes on Bob's end.")
	receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(message.Serialize(), serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		logger.Error("Unable to emulate receiving message as JSON: ", err)
		t.FailNow()
	}

	// Try and decrypt the message and get the message key.
	bobSessionCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	msg, key, err := bobSessionCipher.DecryptMessageReturnKey(ctx, receivedMessage)
	if err != nil {
		logger.Error("Unable to decrypt message: ", err)
		t.FailNow()
	}
	logger.Info("Decrypted message: ", string(msg))
	if string(msg) != string(plaintextMessage) {
		logger.Error("Decrypted string does not match - Encrypted: ", string(plaintextMessage), " Decrypted: ", string(msg))
		t.FailNow()
	}

	// Try using the message key to decrypt the message again.
	logger.Info("Testing using saved message key to decrypt again.")
	for i := 0; i < 10; i++ {
		testDecryptingWithKey(ctx, bobSessionCipher, receivedMessage.WhisperMessage(), key, plaintextMessage, t)
	}
}

func testDecryptingWithKey(ctx context.Context, cipher *session.Cipher, receivedMessage *protocol.SignalMessage, key *message.Keys, plaintextMessage []byte, t *testing.T) {
	msg, err := cipher.DecryptWithKey(ctx, receivedMessage, key)
	if err != nil {
		t.FailNow()
	}
	logger.Info("Decrypted message: ", string(msg))
	if string(msg) != string(plaintextMessage) {
		logger.Error("Decrypted string does not match - Encrypted: ", string(plaintextMessage), " Decrypted: ", string(msg))
		t.FailNow()
	}
}
