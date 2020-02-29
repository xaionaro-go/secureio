package secureio_test

import (
	"context"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/xaionaro-go/secureio"
)

func TestNewIdentity(t *testing.T) {
	dirPath0, err := ioutil.TempDir(os.TempDir(), `secureio-test`)
	assert.NoError(t, err)
	//defer os.RemoveAll(dirPath0)

	dirPath1, err := ioutil.TempDir(os.TempDir(), `secureio-test`)
	assert.NoError(t, err)
	//defer os.RemoveAll(dirPath1)

	identity0, err := NewIdentity(dirPath0)
	assert.NoError(t, err)
	assert.NotNil(t, identity0)

	identity1, err := NewIdentity(dirPath0)
	assert.NoError(t, err)
	assert.NotNil(t, identity1)

	assert.Equal(t, identity0.Keys.Private, identity1.Keys.Private)

	identity2, err := NewIdentityFromPrivateKey(identity0.Keys.Private)
	assert.NoError(t, err)
	assert.NotNil(t, identity2)

	assert.Equal(t, identity0.Keys.Public, identity2.Keys.Public)

	remoteIdentity0, err := NewRemoteIdentity(path.Join(dirPath1, `id_ed25519.pub`))
	assert.Error(t, err)
	assert.Nil(t, remoteIdentity0)

	remoteIdentity0, err = NewRemoteIdentity(path.Join(dirPath0, `/id_ed25519.pub`))
	assert.NoError(t, err)
	assert.NotNil(t, remoteIdentity0)
	assert.Nil(t, remoteIdentity0.Keys.Private)
	assert.NotNil(t, remoteIdentity0.Keys.Public)

	assert.Equal(t, identity0.Keys.Public, remoteIdentity0.Keys.Public)

	remoteIdentity1, err := NewRemoteIdentityFromPublicKey(remoteIdentity0.Keys.Public)
	assert.NoError(t, err)
	assert.NotNil(t, remoteIdentity1)
	assert.Equal(t, remoteIdentity0.Keys.Public, remoteIdentity1.Keys.Public)

	_, err = NewRemoteIdentityFromPublicKey(nil)
	assert.Error(t, err)

	_, err = NewIdentityFromPrivateKey(nil)
	assert.Error(t, err)
}

func TestIdentityMutualConfirmationOfIdentityWithPSK(t *testing.T) {
	identity0, identity1, conn0, conn1 := testPair(t)

	opts := &SessionOptions{}

	opts.KeyExchangerOptions.PSK = make([]byte, 64)
	opts.OnInitFuncs = []OnInitFunc{func(sess *Session) { printLogsOfSession(t, true, sess) }}
	opts.EnableDebug = true
	rand.Read(opts.KeyExchangerOptions.PSK)

	ctx, cancelFunc := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer cancelFunc()

	var wg sync.WaitGroup

	var err0 error
	var keys0 [][]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		keys0, err0 = identity0.MutualConfirmationOfIdentity(
			ctx,
			identity1,
			conn0,
			&testLogger{t, nil},
			opts,
		)
	}()

	var err1 error
	var keys1 [][]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		keys1, err1 = identity1.MutualConfirmationOfIdentity(
			ctx,
			identity0,
			conn1,
			&testLogger{t, nil},
			opts,
		)
	}()

	wg.Wait()

	assert.NoError(t, err0)
	assert.NoError(t, err1)
	assert.Equal(t, keys0, keys1)

	testConnIsOpen(t, conn0, conn1)
}

func TestIdentityMutualConfirmationOfIdentityWithWrongPSK(t *testing.T) {
	identity0, identity1, conn0, conn1 := testPair(t)
	defer conn0.Close()
	defer conn1.Close()

	opts0 := &SessionOptions{}
	opts1 := &SessionOptions{}

	opts0.KeyExchangerOptions.PSK = make([]byte, 64)
	opts1.KeyExchangerOptions.PSK = make([]byte, 64)
	opts0.OnInitFuncs = []OnInitFunc{func(sess *Session) { printLogsOfSession(t, false, sess) }}
	opts1.OnInitFuncs = []OnInitFunc{func(sess *Session) { printLogsOfSession(t, false, sess) }}
	opts0.EnableDebug = true
	opts1.EnableDebug = true
	rand.Read(opts0.KeyExchangerOptions.PSK)
	copy(opts1.KeyExchangerOptions.PSK, opts0.KeyExchangerOptions.PSK)
	opts0.KeyExchangerOptions.PSK[63] = 0
	opts1.KeyExchangerOptions.PSK[63] = 1

	ctx := context.Background()

	var wg sync.WaitGroup

	var err0 error
	var keys0 [][]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		keys0, err0 = identity0.MutualConfirmationOfIdentity(
			ctx,
			identity1,
			conn0,
			//&dummyEventHandler{},
			&testLogger{t, nil},
			opts0,
		)
	}()

	var err1 error
	var keys1 [][]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		keys1, err1 = identity1.MutualConfirmationOfIdentity(
			ctx,
			identity0,
			conn1,
			//&dummyEventHandler{},
			&testLogger{t, nil},
			opts1,
		)
	}()

	wg.Wait()

	assert.Error(t, err0)
	assert.Error(t, err1)
	assert.Nil(t, keys0)
	assert.Nil(t, keys1)

	testConnIsOpen(t, conn0, conn1)
}
