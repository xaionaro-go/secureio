package secureio

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	xerrors "github.com/xaionaro-go/errors"
)

func TestErrTypes(t *testing.T) {
	m := map[reflect.Type]struct{}{}

	for _, err := range []error{
		newErrCannotDecrypt(),
		newErrPartialWrite(),
		newErrInvalidSignature(),
		newErrWrongKeyLength(0, 0),
		newErrCannotLoadKeys(errors.New("unit-test")),
		newErrAlreadyClosed(),
		newErrKeyExchangeTimeout(),
		newErrTooShort(0, 0),
		newErrUnencrypted(),
		newErrInvalidChecksum(nil, nil),
		newErrPayloadTooBig(0, 0),
		newErrMonopolized(),
		newErrNotMonopolized(),
		newErrCanceled(),
		newErrAnswersModeMismatch(0, 0),
		newErrCannotSetReadDeadline(nil),
		newErrCannotPauseOrUnpauseFromThisState(),
		newErrLocalPrivateKeyIsNil(),
		newErrRemotePublicKeyIsNil(),
		newErrRemoteKeyHasNotChanged(),
		newErrInvalidPublicKey(),
	} {
		_ = err.Error() // check if there's no panic

		xerr, ok := err.(*xerrors.Error)
		if !assert.True(t, ok, fmt.Sprintf("%T", err)) {
			continue
		}
		typ := reflect.TypeOf(xerr.Deepest().Err)
		_, alreadyExists := m[typ]
		assert.False(t, alreadyExists, fmt.Sprintf("%T:%v", err, typ))
		m[typ] = struct{}{}
	}

	assert.Nil(t, newErrCannotLoadKeys(nil))
}
