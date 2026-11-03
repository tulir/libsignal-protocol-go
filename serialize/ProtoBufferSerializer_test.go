package serialize

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/util/keyhelper"
)

func TestSignalMessageMacCoversUnknownFields(t *testing.T) {
	sender, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	counter, prevCounter := uint32(0), uint32(0)
	body, err := proto.Marshal(&SignalMessage{
		RatchetKey:      sender.PublicKey().PublicKey().Serialize(),
		Counter:         &counter,
		PreviousCounter: &prevCounter,
		Ciphertext:      make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	body = protowire.AppendTag(body, 7, protowire.VarintType)
	body = protowire.AppendVarint(body, 1)
	macInput := append([]byte{0x33}, body...)
	macKey := make([]byte, 32)
	h := hmac.New(sha256.New, macKey)
	h.Write(sender.PublicKey().PublicKey().Serialize())
	h.Write(receiver.PublicKey().PublicKey().Serialize())
	h.Write(macInput)
	serialized := append(macInput, h.Sum(nil)[:protocol.MacLength]...)

	msg, err := protocol.NewSignalMessageFromBytes(serialized, &ProtoBufSignalMessageSerializer{})
	if err != nil {
		t.Fatal(err)
	}
	if err = msg.VerifyMac(3, sender.PublicKey(), receiver.PublicKey(), macKey); err != nil {
		t.Fatalf("MAC over message with unknown field didn't verify: %v", err)
	}
}
