package secureio

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"testing"
)

type testLogger struct {
	string
	*testing.T
	enableInfo bool
	Session    *Session
}

func (l *testLogger) Error(sess *Session, err error) {
	l.T.Errorf("T:%v:SID:%v", l.T.Name(), sess.ID())
	l.T.Error(err)
	l.T.Errorf("STACK: %v", string(debug.Stack()))
}
func (l *testLogger) Infof(format string, args ...interface{}) {
	if !l.enableInfo {
		fmt.Printf("T:%v:SID:%v: ", l.T.Name(), l.Session.ID())
		fmt.Printf(format+"\n", args...)
		return
	}
	l.T.Errorf(l.string+" [I] "+format, args...)
}
func (l *testLogger) Debugf(format string, args ...interface{}) {
	fmt.Printf("T:%v:SID:%v: ", l.T.Name(), l.Session.ID())
	fmt.Printf(format+"\n", args...)
}
func (l *testLogger) OnConnect(sess *Session) {
}
func (l *testLogger) OnInit(sess *Session) {
	l.Session = sess
}
func (l *testLogger) IsDebugEnabled() bool {
	return true
}

type pipeReadWriter struct {
	Prefix string
	io.Reader
	io.Writer
}

func (p *pipeReadWriter) Close() error {
	return nil
}

func (p *pipeReadWriter) Read(b []byte) (int, error) {
	n, err := p.Reader.Read(b)
	return n, err
}

func (p *pipeReadWriter) Write(b []byte) (int, error) {
	n, err := p.Writer.Write(b)

	return n, err
}

func testPair(t *testing.T) (identity0, identity1 *Identity, conn0, conn1 *pipeReadWriter) {
	var err error

	dir := `/tmp/.test_xaionaro-go_secureio_session_`
	_ = os.Mkdir(dir+"0", 0700)
	_ = os.Mkdir(dir+"1", 0700)
	identity0, err = NewIdentity(dir + "0")
	if err != nil {
		t.Fatal(err)
	}
	identity1, err = NewIdentity(dir + "1")
	if err != nil {
		t.Fatal(err)
	}

	pipeR0, pipeW0, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	pipeR1, pipeW1, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	conn0 = &pipeReadWriter{
		Prefix: "0",
		Reader: pipeR0,
		Writer: pipeW1,
	}

	conn1 = &pipeReadWriter{
		Prefix: "1",
		Reader: pipeR1,
		Writer: pipeW0,
	}

	return
}
