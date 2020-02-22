package secureio

import (
	"fmt"
	"io"

	"golang.org/x/crypto/poly1305"

	"github.com/xaionaro-go/errors"
)

func wrapError(err error) error {
	if err == nil {
		return nil
	}
	wrappedErr := errors.Wrap(err)
	wrappedErr.(*errors.Error).Traceback.CutOffFirstNLines++
	return wrappedErr
}

// ErrCannotDecrypt is an error indicates it was unable to
// decrypt a message. So all three attempts failed:
// * Try to decrypt using current cipher key.
// * Try to decrypt using previous cipher key.
// * Try to interpret it as already a non-encrypted message.
type ErrCannotDecrypt struct{}

func newErrCannotDecrypt() error {
	err := errors.New(ErrCannotDecrypt{})
	err.Traceback.CutOffFirstNLines++
	return err
}
func (err ErrCannotDecrypt) Error() string {
	return "cannot decrypt"
}

// ErrPartialWrite is an error indicates if a Write() call returned "n"
// less than expected. Could be a connection-related problem.
type ErrPartialWrite struct{}

func newErrPartialWrite() error {
	err := errors.New(ErrPartialWrite{})
	err.Traceback.CutOffFirstNLines++
	return err
}
func (err ErrPartialWrite) Error() string {
	return "partial write"
}

// ErrInvalidSignature is an error indicates if the remote side have
// sent a signature which fails to be verified by the known
// public key (of the remote side).
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

// ErrWrongKeyLength is an error indicates when a crypto key is of a wrong size.
// For example ED25519 key is expected to be 256 bits (no more, no less).
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

// ErrCannotLoadKeys is an error indicates if it was unable to read or/and parse
// crypto keys.
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

// ErrAlreadyClosed is an error indicates there was an attempt
// to use a resource which is already marked as closed.
// For example, it could mean a try to use a closed session or connection.
type ErrAlreadyClosed struct{}

func newErrAlreadyClosed() error {
	err := errors.New(ErrAlreadyClosed{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrAlreadyClosed) Error() string {
	return "already closed"
}

// ErrKeyExchangeTimeout is an error indicates that there was no
// successful key exchange too long. So this session does not work properly
// or/and cannot be trusted and therefore considered erroneous.
type ErrKeyExchangeTimeout struct{}

func newErrKeyExchangeTimeout() error {
	err := errors.New(ErrKeyExchangeTimeout{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrKeyExchangeTimeout) Error() string {
	return "key exchange timeout"
}

// ErrTooShort is an error used when it was unable to parse something
// because the data (in the binary representation) is too short.
// For example if there was received only one byte while it
// was expecting for message headers (which are a structure of a static
// size larger than one byte).
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

// ErrUnencrypted is an error indicates that the parsed message was
// not encrypted.
type ErrUnencrypted struct{}

func newErrUnencrypted() error {
	err := errors.New(ErrUnencrypted{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrUnencrypted) Error() string {
	return "not encrypted"
}

// ErrInvalidChecksum is an error indicates if decrypted checksum does
// not match checksum of the decrypted data with any
// currently available cipher key.
type ErrInvalidChecksum struct {
	ExpectedChecksum [poly1305.TagSize]byte
	RealChecksum     [poly1305.TagSize]byte
}

func newErrInvalidChecksum(expectedChecksum, realChecksum []byte) error {
	origErr := ErrInvalidChecksum{}
	copy(origErr.ExpectedChecksum[:], expectedChecksum)
	copy(origErr.RealChecksum[:], realChecksum)
	err := errors.New(origErr)
	err.Traceback.CutOffFirstNLines += 2
	err.Format = errors.FormatOneLine
	return err
}
func (err ErrInvalidChecksum) Error() string {
	return fmt.Sprintf("checksum mismatch: %x != %x",
		err.RealChecksum, err.ExpectedChecksum)
}

// ErrPayloadTooBig means there was an attempt to use more buffer
// space than it was reserved. The size of a message should not
// exceed (*Session).GetMaxPayloadSize() bytes.
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

// errMonopolized is an error means that there was an attempt to lock a buffer
// which is already locked by an exclusive locking. This cases are
// handled just by retries.
type errMonopolized struct{}

func newErrMonopolized() error {
	err := errors.New(errMonopolized{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err errMonopolized) Error() string {
	return fmt.Sprintf("the payload is too big")
}

// ErrCanceled is an error indicates that the action was canceled. It
// happens when there're active async-requests while session is
// already closing.
type ErrCanceled struct{}

func newErrCanceled() error {
	err := errors.New(ErrCanceled{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrCanceled) Error() string {
	return fmt.Sprintf("canceled")
}

type ErrAnswersModeMismatch struct {
	AnswersModeLocal  KeyExchangeAnswersMode
	AnswersModeRemote KeyExchangeAnswersMode
}

func newErrAnswersModeMismatch(answersModeLocal, answersModeRemote KeyExchangeAnswersMode) error {
	err := errors.New(ErrAnswersModeMismatch{answersModeLocal, answersModeRemote})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrAnswersModeMismatch) Error() string {
	return fmt.Sprintf("[kx] AnswersMode does not match: local:%v != remote:%v", err.AnswersModeLocal, err.AnswersModeRemote)
}

type ErrCannotSetReadDeadline struct {
	Backend io.ReadWriteCloser
}

func newErrCannotSetReadDeadline(backend io.ReadWriteCloser) error {
	err := errors.New(ErrCannotSetReadDeadline{Backend: backend})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrCannotSetReadDeadline) Error() string {
	return fmt.Sprintf("do not know how to set ReadDeadline on %T", err.Backend)
}

type ErrCannotPauseFromThisState struct{}

func newErrCannotPauseFromThisState() error {
	err := errors.New(ErrCannotPauseFromThisState{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrCannotPauseFromThisState) Error() string {
	return fmt.Sprintf("cannot pause from this state")
}
