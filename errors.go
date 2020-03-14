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
	err := errors.New(ErrInvalidSignature{})
	err.Traceback.CutOffFirstNLines++
	return err
}
func (err ErrInvalidSignature) Error() string {
	return "invalid signature"
}

/*
var (
	errUnencrypted           = errors.New(`unencrypted message`)
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
	return fmt.Sprintf("wrong key length: real:%d != expected:%d",
		err.RealLength, err.ExpectedLength)
}

// ErrCannotLoadKeys is an error indicates if it was unable to read or/and parse
// crypto keys.
type ErrCannotLoadKeys struct {
	OriginalError error
}

func newErrCannotLoadKeys(origErr error) error {
	err := errors.Wrap(origErr, ErrCannotLoadKeys{origErr})
	if xerr, ok := err.(*errors.Error); ok {
		xerr.Traceback.CutOffFirstNLines += 2
	}
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

// errUnencrypted is an error indicates that the parsed message was
// not encrypted.
type errUnencrypted struct{}

func newErrUnencrypted() error {
	err := errors.New(errUnencrypted{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err errUnencrypted) Error() string {
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
	return fmt.Sprintf("buffer is monopolized (this is an internal error that should never be visible to anywhere outside of this package)")
}

// errNotMonopolized is an error means that there was an attempt to free a buffer
// which is already free.
type errNotMonopolized struct{}

func newErrNotMonopolized() error {
	err := errors.New(errNotMonopolized{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err errNotMonopolized) Error() string {
	return fmt.Sprintf("buffer is not monopolized (this is an internal error that should never be visible to anywhere outside of this package)")
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

// ErrAnswersModeMismatch is reported when local and remote side
// has different settings of KeyExchangerOptions.AnswersMode
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

// ErrCannotSetReadDeadline is returned if it was an attempt
// to use "Detach" (see SessionOptions) functions or "SetPause" on
// a session created over io.ReadWriteCloser which does not
// implement any of methods: `SetReadDeadline` and `SetDeadline`.
type ErrCannotSetReadDeadline struct {
	Backend io.ReadWriter
}

func newErrCannotSetReadDeadline(backend io.ReadWriter) error {
	err := errors.New(ErrCannotSetReadDeadline{Backend: backend})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrCannotSetReadDeadline) Error() string {
	return fmt.Sprintf("do not know how to set ReadDeadline on %T", err.Backend)
}

// ErrCannotPauseOrUnpauseFromThisState is returned by SetPause()
// if the session is not in a required state.
//
// To pause a session it must be in state SessionStateEstablished.
// To unpause a session it must be in state SessionStatePaused.
type ErrCannotPauseOrUnpauseFromThisState struct{}

func newErrCannotPauseOrUnpauseFromThisState() error {
	err := errors.New(ErrCannotPauseOrUnpauseFromThisState{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err ErrCannotPauseOrUnpauseFromThisState) Error() string {
	return fmt.Sprintf("cannot pause/unpause from this state")
}

type errLocalPrivateKeyIsNil struct{}

func newErrLocalPrivateKeyIsNil() *errors.Error {
	err := errors.New(errLocalPrivateKeyIsNil{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err errLocalPrivateKeyIsNil) Error() string {
	return fmt.Sprintf("[curve25519] local private key is nil")
}

type errRemotePublicKeyIsNil struct{}

func newErrRemotePublicKeyIsNil() *errors.Error {
	err := errors.New(errRemotePublicKeyIsNil{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err errRemotePublicKeyIsNil) Error() string {
	return fmt.Sprintf("[curve25519] remote public key is nil")
}

type errRemoteKeyHasNotChanged struct{}

func newErrRemoteKeyHasNotChanged() error {
	err := errors.New(errRemoteKeyHasNotChanged{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}

func (err errRemoteKeyHasNotChanged) Error() string {
	return fmt.Sprintf("[kx] remote key has not changed")
}

type errInvalidPublicKey struct{}

func newErrInvalidPublicKey() error {
	err := errors.New(errInvalidPublicKey{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err errInvalidPublicKey) Error() string {
	return fmt.Sprintf("[kx] invalid public key")
}

type errUnableToLock struct{}

func newErrUnableToLock() error {
	err := errors.New(errUnableToLock{})
	err.Traceback.CutOffFirstNLines += 2
	return err
}
func (err errUnableToLock) Error() string {
	return fmt.Sprintf("unable to get a lock")
}
