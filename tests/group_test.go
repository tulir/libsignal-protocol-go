package tests

import (
	"context"
	"testing"

	"go.mau.fi/libsignal/groups"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/logger"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/session"
)

// TestGroupSessionBuilder checks building of a group session.
func TestGroupSessionBuilder(t *testing.T) {
	ctx := context.Background()

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)
	groupName := "123"

	// ***** Build one-to-one session with group members *****

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	// Create a PreKeyBundle from Bob's prekey records and other
	// data.
	logger.Debug("Fetching Bob's prekey with ID: ", bob.preKeys[0].ID())
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
	logger.Debug("Building sender's (Alice) session...")
	err := alice.sessionBuilder.ProcessBundle(ctx, retrivedPreKey)
	if err != nil {
		logger.Error("Unable to process retrieved prekey bundle")
		t.FailNow()
	}

	// Create a session builder to create a session between Alice -> Bob.
	aliceSenderKeyName := protocol.NewSenderKeyName(groupName, alice.address)
	aliceSkdm, err := alice.groupBuilder.Create(ctx, aliceSenderKeyName)
	if err != nil {
		logger.Error("Unable to create group session")
		t.FailNow()
	}
	aliceSendingCipher := groups.NewGroupCipher(alice.groupBuilder, aliceSenderKeyName, alice.senderKeyStore)

	// Create a one-to-one session cipher to encrypt the skdm to Bob.
	aliceBobSessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	encryptedSkdm, err := aliceBobSessionCipher.Encrypt(ctx, aliceSkdm.Serialize())
	if err != nil {
		logger.Error("Unable to encrypt message: ", err)
		t.FailNow()
	}

	// ***** Bob receive senderkey distribution message from Alice *****

	// Emulate receiving the message as JSON over the network.
	logger.Debug("Building message from bytes on Bob's end.")
	receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(encryptedSkdm.Serialize(), serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		logger.Error("Unable to emulate receiving message as JSON: ", err)
		t.FailNow()
	}

	// Try and decrypt the senderkey distribution message
	bobAliceSessionCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	msg, err := bobAliceSessionCipher.DecryptMessage(ctx, receivedMessage)
	if err != nil {
		logger.Error("Unable to decrypt message: ", err)
		t.FailNow()
	}
	bobReceivedSkdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(msg, serializer.SenderKeyDistributionMessage)
	if err != nil {
		logger.Error("Unable to create senderkey distribution message from bytes: ", err)
		t.FailNow()
	}

	// ***** Alice Send *****

	// Encrypt some messages to send with Alice's group cipher
	logger.Debug("Alice sending messages to Bob...")
	alicePlainMessages, aliceEncryptedMessages := sendGroupMessages(1000, aliceSendingCipher, serializer, t)

	// Build bob's side of the session.
	bob.groupBuilder.Process(ctx, aliceSenderKeyName, bobReceivedSkdm)
	receivingBobCipher := groups.NewGroupCipher(bob.groupBuilder, aliceSenderKeyName, bob.senderKeyStore)

	// Decrypt the messages sent by alice.
	logger.Debug("Bob receiving messages from Alice...")
	receiveGroupMessages(aliceEncryptedMessages, alicePlainMessages, receivingBobCipher, t)

	// ***** Bob send senderkey distribution message to Alice *****

	// Create a group builder with Bob's address.
	bobSenderKeyName := protocol.NewSenderKeyName(groupName, bob.address)
	bobSkdm, err := bob.groupBuilder.Create(ctx, bobSenderKeyName)
	if err != nil {
		logger.Error("Unable to create group session")
		t.FailNow()
	}
	bobSendingCipher := groups.NewGroupCipher(bob.groupBuilder, bobSenderKeyName, bob.senderKeyStore)

	// Encrypt the senderKey distribution message to send to Alice.
	bobEncryptedSkdm, err := bobAliceSessionCipher.Encrypt(ctx, bobSkdm.Serialize())
	if err != nil {
		logger.Error("Unable to encrypt message: ", err)
		t.FailNow()
	}

	// Emulate receiving the message as JSON over the network.
	logger.Debug("Building message from bytes on Alice's end.")
	aliceReceivedMessage, err := protocol.NewSignalMessageFromBytes(bobEncryptedSkdm.Serialize(), serializer.SignalMessage)
	if err != nil {
		logger.Error("Unable to emulate receiving message as JSON: ", err)
		t.FailNow()
	}

	// ***** Alice receives senderkey distribution message from Bob *****

	// Decrypt the received message.
	msg, err = aliceBobSessionCipher.Decrypt(ctx, aliceReceivedMessage)
	if err != nil {
		logger.Error("Unable to decrypt message: ", err)
		t.FailNow()
	}
	aliceReceivedSkdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(msg, serializer.SenderKeyDistributionMessage)
	if err != nil {
		logger.Error("Unable to create senderkey distribution message from bytes: ", err)
		t.FailNow()
	}

	// ***** Bob Send *****

	// Encrypt some messages to send with Bob's group cipher
	logger.Debug("Bob sending messages to Alice...")
	bobPlainMessages, bobEncryptedMessages := sendGroupMessages(1000, bobSendingCipher, serializer, t)

	// Build alice's side of the session.
	alice.groupBuilder.Process(ctx, bobSenderKeyName, aliceReceivedSkdm)
	receivingAliceCipher := groups.NewGroupCipher(alice.groupBuilder, bobSenderKeyName, alice.senderKeyStore)

	// Decrypt the messages sent by bob.
	logger.Debug("Alice receiving messages from Bob...")
	receiveGroupMessages(bobEncryptedMessages, bobPlainMessages, receivingAliceCipher, t)
}

// sendGroupMessages will generate and return a list of plaintext and encrypted messages.
func sendGroupMessages(count int, cipher *groups.GroupCipher, serializer *serialize.Serializer, t *testing.T) ([]string, []protocol.CiphertextMessage) {
	ctx := context.Background()
	texts := []string{
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.",
		"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.",
		"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
	}
	messageStrings := make([]string, count)
	for i := 0; i < count; i++ {
		messageStrings[i] = texts[i%len(texts)]
	}

	messages := make([]protocol.CiphertextMessage, count)
	for i, str := range messageStrings {
		msg := encryptGroupMessage(ctx, str, cipher, serializer, t)
		messages[i] = msg
	}

	return messageStrings, messages
}

// receiveMessages is a helper function to receive a bunch of encrypted messages and decrypt them.
func receiveGroupMessages(messages []protocol.CiphertextMessage, messageStrings []string, cipher *groups.GroupCipher, t *testing.T) {
	ctx := context.Background()
	for i, receivedMessage := range messages {
		msg := decryptGroupMessage(ctx, receivedMessage, cipher, t)
		if messageStrings[i] != msg {
			logger.Error("Decrypted message does not match original: ", messageStrings[i], " != ", msg)
			t.FailNow()
		}
	}
}

// encryptMessage is a helper function to send encrypted messages with the given cipher.
func encryptGroupMessage(ctx context.Context, message string, cipher *groups.GroupCipher, serializer *serialize.Serializer, t *testing.T) protocol.CiphertextMessage {
	plaintextMessage := []byte(message)
	logger.Info("Encrypting message: ", string(plaintextMessage))
	encrypted, err := cipher.Encrypt(ctx, plaintextMessage)
	if err != nil {
		logger.Error("Unable to encrypt message: ", err)
		t.FailNow()
	}
	logger.Info("Encrypted message: ", encrypted)

	// Emulate receiving the message as JSON over the network.
	logger.Debug("Building message from bytes to emulate sending over the network.")
	var encryptedMessage protocol.CiphertextMessage
	switch encrypted.(type) {
	case *protocol.SenderKeyMessage:
		message := encrypted.(*protocol.SenderKeyMessage)
		encryptedMessage, err = protocol.NewSenderKeyMessageFromBytes(message.SignedSerialize(), serializer.SenderKeyMessage)
		if err != nil {
			logger.Error("Unable to emulate receiving message as JSON: ", err)
			t.FailNow()
		}
	}
	logger.Info(encryptedMessage)

	return encryptedMessage
}

// decryptMessage is a helper function to decrypt messages of a session.
func decryptGroupMessage(ctx context.Context, message protocol.CiphertextMessage, cipher *groups.GroupCipher, t *testing.T) string {
	senderKeyMessage := message.(*protocol.SenderKeyMessage)
	//if !ok {
	//	logger.Error("Wrong message type in decrypting group message.")
	//	t.FailNow()
	//}

	msg, err := cipher.Decrypt(ctx, senderKeyMessage)
	if err != nil {
		logger.Error("Unable to decrypt message: ", err)
		t.FailNow()
	}
	logger.Info("Decrypted message: ", string(msg))

	return string(msg)
}
