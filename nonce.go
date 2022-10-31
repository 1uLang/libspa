package libspa

import (
	"crypto/rand"
	"github.com/pkg/errors"
)

type Nonce []byte

func RandomNonce() (Nonce, error) {
	nonce := make([]byte, nonceFieldSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return Nonce{}, errors.Wrap(err, "generating random nonce")
	}

	return nonce, nil
}
