package record

import (
	"crypto/mlkem"
	"fmt"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/identity"
)

type KyberPreKey struct {
	ID         uint32
	Seed       []byte
	Signature  []byte
	Timestamp  int64
	LastResort bool
}

func GenerateKyberPreKey(id uint32, identityKey *identity.KeyPair, timestamp int64, lastResort bool) (*KyberPreKey, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	sig := ecc.CalculateSignature(identityKey.PrivateKey(), dk.EncapsulationKey().Bytes())
	return &KyberPreKey{
		ID:         id,
		Seed:       dk.Bytes(),
		Signature:  sig[:],
		Timestamp:  timestamp,
		LastResort: lastResort,
	}, nil
}

func (k *KyberPreKey) decapsulationKey() (*mlkem.DecapsulationKey1024, error) {
	if k == nil {
		return nil, fmt.Errorf("missing kyber prekey")
	}
	return mlkem.NewDecapsulationKey1024(k.Seed)
}

func (k *KyberPreKey) PublicKey() ([]byte, error) {
	dk, err := k.decapsulationKey()
	if err != nil {
		return nil, err
	}
	return dk.EncapsulationKey().Bytes(), nil
}

func (k *KyberPreKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	dk, err := k.decapsulationKey()
	if err != nil {
		return nil, err
	}
	return dk.Decapsulate(ciphertext)
}
