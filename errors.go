package secureio

import (
	"fmt"
	"strings"

	"github.com/xaionaro-go/errors"
)

func wrapErrorf(format string, args ...interface{}) error {
	errI := args[len(args)-1]
	err, _ := errI.(error)
	if errI != nil && err == nil {
		return nil // nil error, nothing to wrap
	}

	if err == nil {
		return errors.New(fmt.Errorf(format, args...))
	}
	args = args[:len(args)-1]

	var parentErr error
	if strings.HasSuffix(format, ": %w") {
		parentErr = fmt.Errorf(format[:len(format)-4], args...)
	} else {
		parentErr = fmt.Errorf(format, args...)
	}
	parentErrForWrap := errors.New(parentErr)
	parentErrForWrap.Traceback = nil
	return errors.Wrap(err, parentErrForWrap)
}

func wrapError(err error) error {
	if err == nil {
		return nil
	}
	wrappedErr := errors.Wrap(err)
	wrappedErr.(*errors.Error).Traceback.CutOffFirstNLines++
	return wrappedErr
}

type ErrCannotDecrypt struct{}

func newErrCannotDecrypt() error {
	err := errors.New(ErrCannotDecrypt{})
	err.Traceback.CutOffFirstNLines++
	return err
}
func (err ErrCannotDecrypt) Error() string {
	return "cannot decrypt"
}

type ErrPartialWrite struct{}

func newErrPartialWrite() error {
	err := errors.New(ErrPartialWrite{})
	err.Traceback.CutOffFirstNLines++
	return err
}
func (err ErrPartialWrite) Error() string {
	return "partial write"
}

type ErrInvalidSignature struct{}

func newErrInvalidSignature() error {
	err := errors.New(ErrPartialWrite{})
	err.Traceback.CutOffFirstNLines++
	return err
}
func (err ErrInvalidSignature) Error() string {
	return "invalid signature"
}

/*
var (
	ErrUnencrypted           = errors.New(`unencrypted message`)
	ErrCannotCreateNewCipher = errors.New(`cannot create a new cipher instance`)
	ErrTooBig                = errors.New("message is too big")
	ErrAlreadyClosed         = errors.New("already closed")
	ErrInvalidChecksum       = errors.New("invalid checksum (or invalid encryption key)")
	ErrInvalidLength         = errors.New("invalid length")
	ErrEmptyInput            = errors.New("empty input")
	ErrClosed                = errors.New("closed")
)

var (
	ErrWrongKeySeedLength = errors.New("wrong length of the key seed")
	ErrKeyExchangeTimeout = errors.New("key exchange timeout")
)

*/

type ErrWrongKeyLength struct {
	ExpectedLength uint
	RealLength     uint
}

func newErrWrongKeyLength(expectedLength, realLength uint) error {
	err := errors.New(ErrWrongKeyLength{expectedLength, realLength})
	err.Traceback.CutOffFirstNLines++
	return err
}

func (err ErrWrongKeyLength) Error() string {
	return fmt.Sprintf("wrong key length: %d != %d",
		err.RealLength, err.ExpectedLength)
}

type ErrCannotLoadKeys struct {
	OriginalError error
}

func newErrCannotLoadKeys(origErr error) error {
	err := errors.Wrap(origErr, ErrCannotLoadKeys{origErr}).(*errors.Error)
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrCannotLoadKeys) Error() string {
	return "cannot load keys"
}

type ErrAlreadyClosed struct{}

func newErrAlreadyClosed() error {
	err := errors.New(ErrAlreadyClosed{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrAlreadyClosed) Error() string {
	return "already closed"
}

type ErrKeyExchangeTimeout struct{}

func newErrKeyExchangeTimeout() error {
	err := errors.New(ErrKeyExchangeTimeout{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrKeyExchangeTimeout) Error() string {
	return "key exchange timeout"
}

type ErrTooShort struct {
	ExpectedLength uint
	RealLength     uint
}

func newErrTooShort(expectedLength, realLength uint) error {
	err := errors.New(ErrTooShort{
		ExpectedLength: expectedLength,
		RealLength:     realLength,
	})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrTooShort) Error() string {
	return "too short"
}

type ErrUnencrypted struct{}

func newErrUnencrypted() error {
	err := errors.New(ErrUnencrypted{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrUnencrypted) Error() string {
	return "not encrypted"
}

type ErrInvalidChecksum struct {
	ExpectedChecksum uint64
	RealChecksum     uint64
}

func newErrInvalidChecksum(expectedChecksum, realChecksum uint64) error {
	err := errors.New(ErrInvalidChecksum{
		ExpectedChecksum: expectedChecksum,
		RealChecksum:     realChecksum,
	})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrInvalidChecksum) Error() string {
	return fmt.Sprintf("checksum mismatch: 0x%x != 0x%x",
		err.RealChecksum, err.ExpectedChecksum)
}

type ErrPayloadTooBig struct {
	MaxSize  uint
	RealSize uint
}

func newErrPayloadTooBig(maxSize, realSize uint) error {
	err := errors.New(ErrPayloadTooBig{maxSize, realSize})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrPayloadTooBig) Error() string {
	return fmt.Sprintf("the payload is too big (%v > %v)", err.RealSize, err.MaxSize)
}

type ErrMonopolized struct{}

func newErrMonopolized() error {
	err := errors.New(ErrMonopolized{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrMonopolized) Error() string {
	return fmt.Sprintf("the payload is too big")
}

type ErrCanceled struct{}

func newErrCanceled() error {
	err := errors.New(ErrCanceled{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrCanceled) Error() string {
	return fmt.Sprintf("canceled")
}
