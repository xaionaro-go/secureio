package cryptofilter

import (
	"io"
	"os"
	"testing"
)

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

type testLogger struct {
	string
	*testing.T
}

func (l *testLogger) Error(err error) {
	l.T.Error(err)
}
func (l *testLogger) Infof(fmt string, args ...interface{}) {
	l.T.Errorf(l.string+" [I] "+fmt, args...)
}
func (l *testLogger) Debugf(fmt string, args ...interface{}) {
}

func TestSession(t *testing.T) {
	dir := `/tmp/.test_xaionaro-go_cryptofilter_session_`
	_ = os.Mkdir(dir+"0", 0700)
	_ = os.Mkdir(dir+"1", 0700)
	identity0, err := NewIdentity(dir + "0")
	if err != nil {
		t.Fatal(err)
	}
	identity1, err := NewIdentity(dir + "1")
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

	conn0 := &pipeReadWriter{
		Prefix: "0",
		Reader: pipeR0,
		Writer: pipeW1,
	}

	conn1 := &pipeReadWriter{
		Prefix: "1",
		Reader: pipeR1,
		Writer: pipeW0,
	}

	sess0 := identity0.NewSession(identity1, conn0, &testLogger{"0", t})
	sess1 := identity1.NewSession(identity0, conn1, &testLogger{"1", t})

	_, err = sess0.Write([]byte(`test`))
	if err != nil {
		t.Fatal(err)
	}

	r := make([]byte, 4)
	_, err = sess1.Read(r)
	if err != nil {
		t.Fatal(err)
	}

	if string(r) != `test` {
		t.Error(`received string not equals to "test"`)
	}
}
