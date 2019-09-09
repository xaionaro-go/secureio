package secureio

import (
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"testing"

	"github.com/xaionaro-go/errors"
)

type testLogger struct {
	string
	*testing.T
	enableInfo  bool
	enableDebug bool
	Session     *Session
}

func (l *testLogger) Error(sess *Session, err error) {
	xerr := err.(*errors.Error)
	if xerr.Has(io.EOF) {
		return
	}
	l.T.Errorf("E:%v:SID:%v:%v", l.T.Name(), sess.ID(), xerr)
}
func (l *testLogger) Infof(format string, args ...interface{}) {
	if !l.enableInfo {
		fmt.Printf("I:%v:SID:%v: "+format+"\n",
			append([]interface{}{l.T.Name(), l.Session.ID()}, args...)...)
		return
	}
	l.T.Errorf(l.string+" [I] "+format, args...)
}
func (l *testLogger) Debugf(format string, args ...interface{}) {
	fmt.Printf("D:%v:SID:%v: "+format+"\n",
		append([]interface{}{l.T.Name(), l.Session.ID()}, args...)...)
}
func (l *testLogger) OnConnect(sess *Session) {
}
func (l *testLogger) OnInit(sess *Session) {
	l.Session = sess
}
func (l *testLogger) IsDebugEnabled() bool {
	return l.enableDebug
}

type pipeReadWriter struct {
	Prefix string
	io.ReadCloser
	io.WriteCloser
}

func (p *pipeReadWriter) Close() error {
	p.ReadCloser.Close()
	p.WriteCloser.Close()
	return nil
}

func (p *pipeReadWriter) Read(b []byte) (int, error) {
	n, err := p.ReadCloser.Read(b)
	return n, err
}

func (p *pipeReadWriter) Write(b []byte) (int, error) {
	n, err := p.WriteCloser.Write(b)

	return n, err
}

func testPair(t *testing.T) (identity0, identity1 *Identity, conn0, conn1 *pipeReadWriter) {
	var err error

	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

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
		Prefix:      "0",
		ReadCloser:  pipeR0,
		WriteCloser: pipeW1,
	}

	conn1 = &pipeReadWriter{
		Prefix:      "1",
		ReadCloser:  pipeR1,
		WriteCloser: pipeW0,
	}

	return
}
