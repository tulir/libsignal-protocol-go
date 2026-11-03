package store

import (
	"context"

	"go.mau.fi/libsignal/state/record"
)

type KyberPreKey interface {
	LoadKyberPreKey(ctx context.Context, kyberPreKeyID uint32) (*record.KyberPreKey, error)
	MarkKyberPreKeyUsed(ctx context.Context, kyberPreKeyID uint32) error
}
