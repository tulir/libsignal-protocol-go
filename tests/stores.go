package tests

import (
	"context"

	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/state/record"
)

// Define some in-memory stores for testing.

// IdentityKeyStore
func NewInMemoryIdentityKey(identityKey *identity.KeyPair, localRegistrationID uint32) *InMemoryIdentityKey {
	return &InMemoryIdentityKey{
		trustedKeys:         make(map[*protocol.SignalAddress]*identity.Key),
		identityKeyPair:     identityKey,
		localRegistrationID: localRegistrationID,
	}
}

type InMemoryIdentityKey struct {
	trustedKeys         map[*protocol.SignalAddress]*identity.Key
	identityKeyPair     *identity.KeyPair
	localRegistrationID uint32
}

func (i *InMemoryIdentityKey) GetIdentityKeyPair() *identity.KeyPair {
	return i.identityKeyPair
}

func (i *InMemoryIdentityKey) GetLocalRegistrationID() uint32 {
	return i.localRegistrationID
}

func (i *InMemoryIdentityKey) SaveIdentity(ctx context.Context, address *protocol.SignalAddress, identityKey *identity.Key) error {
	i.trustedKeys[address] = identityKey
	return nil
}

func (i *InMemoryIdentityKey) IsTrustedIdentity(ctx context.Context, address *protocol.SignalAddress, identityKey *identity.Key) (bool, error) {
	trusted := i.trustedKeys[address]
	return (trusted == nil || trusted.Fingerprint() == identityKey.Fingerprint()), nil
}

// PreKeyStore
func NewInMemoryPreKey() *InMemoryPreKey {
	return &InMemoryPreKey{
		store: make(map[uint32]*record.PreKey),
	}
}

type InMemoryPreKey struct {
	store map[uint32]*record.PreKey
}

func (i *InMemoryPreKey) LoadPreKey(ctx context.Context, preKeyID uint32) (*record.PreKey, error) {
	return i.store[preKeyID], nil
}

func (i *InMemoryPreKey) StorePreKey(ctx context.Context, preKeyID uint32, preKeyRecord *record.PreKey) error {
	i.store[preKeyID] = preKeyRecord
	return nil
}

func (i *InMemoryPreKey) ContainsPreKey(ctx context.Context, preKeyID uint32) (bool, error) {
	_, ok := i.store[preKeyID]
	return ok, nil
}

func (i *InMemoryPreKey) RemovePreKey(ctx context.Context, preKeyID uint32) error {
	delete(i.store, preKeyID)
	return nil
}

// SessionStore
func NewInMemorySession(serializer *serialize.Serializer) *InMemorySession {
	return &InMemorySession{
		sessions:   make(map[*protocol.SignalAddress]*record.Session),
		serializer: serializer,
	}
}

type InMemorySession struct {
	sessions   map[*protocol.SignalAddress]*record.Session
	serializer *serialize.Serializer
}

func (i *InMemorySession) LoadSession(ctx context.Context, address *protocol.SignalAddress) (*record.Session, error) {
	contains, err := i.ContainsSession(ctx, address)
	if err != nil {
		return nil, err
	}
	if contains {
		return i.sessions[address], nil
	}
	sessionRecord := record.NewSession(i.serializer.Session, i.serializer.State)
	i.sessions[address] = sessionRecord

	return sessionRecord, nil
}

func (i *InMemorySession) GetSubDeviceSessions(ctx context.Context, name string) ([]uint32, error) {
	var deviceIDs []uint32

	for key := range i.sessions {
		if key.Name() == name && key.DeviceID() != 1 {
			deviceIDs = append(deviceIDs, key.DeviceID())
		}
	}

	return deviceIDs, nil
}

func (i *InMemorySession) StoreSession(ctx context.Context, remoteAddress *protocol.SignalAddress, record *record.Session) error {
	i.sessions[remoteAddress] = record
	return nil
}

func (i *InMemorySession) ContainsSession(ctx context.Context, remoteAddress *protocol.SignalAddress) (bool, error) {
	_, ok := i.sessions[remoteAddress]
	return ok, nil
}

func (i *InMemorySession) DeleteSession(ctx context.Context, remoteAddress *protocol.SignalAddress) error {
	delete(i.sessions, remoteAddress)
	return nil
}

func (i *InMemorySession) DeleteAllSessions(ctx context.Context) error {
	i.sessions = make(map[*protocol.SignalAddress]*record.Session)
	return nil
}

// SignedPreKeyStore
func NewInMemorySignedPreKey() *InMemorySignedPreKey {
	return &InMemorySignedPreKey{
		store: make(map[uint32]*record.SignedPreKey),
	}
}

type InMemorySignedPreKey struct {
	store map[uint32]*record.SignedPreKey
}

func (i *InMemorySignedPreKey) LoadSignedPreKey(ctx context.Context, signedPreKeyID uint32) (*record.SignedPreKey, error) {
	return i.store[signedPreKeyID], nil
}

func (i *InMemorySignedPreKey) LoadSignedPreKeys(ctx context.Context) ([]*record.SignedPreKey, error) {
	var preKeys []*record.SignedPreKey

	for _, record := range i.store {
		preKeys = append(preKeys, record)
	}

	return preKeys, nil
}

func (i *InMemorySignedPreKey) StoreSignedPreKey(ctx context.Context, signedPreKeyID uint32, record *record.SignedPreKey) error {
	i.store[signedPreKeyID] = record
	return nil
}

func (i *InMemorySignedPreKey) ContainsSignedPreKey(ctx context.Context, signedPreKeyID uint32) (bool, error) {
	_, ok := i.store[signedPreKeyID]
	return ok, nil
}

func (i *InMemorySignedPreKey) RemoveSignedPreKey(ctx context.Context, signedPreKeyID uint32) error {
	delete(i.store, signedPreKeyID)
	return nil
}

func NewInMemorySenderKey() *InMemorySenderKey {
	return &InMemorySenderKey{
		store: make(map[*protocol.SenderKeyName]*groupRecord.SenderKey),
	}
}

type InMemorySenderKey struct {
	store map[*protocol.SenderKeyName]*groupRecord.SenderKey
}

func (i *InMemorySenderKey) StoreSenderKey(ctx context.Context, senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) error {
	i.store[senderKeyName] = keyRecord
	return nil
}

func (i *InMemorySenderKey) LoadSenderKey(ctx context.Context, senderKeyName *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	return i.store[senderKeyName], nil
}
