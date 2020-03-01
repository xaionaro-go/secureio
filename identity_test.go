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

func testIdentityMutualConfirmationOfIdentityWithPSKs(t *testing.T, shouldFail bool, psk0, psk1 []byte) {
	identity0, identity1, conn0, conn1 := testPair(t)
	defer conn0.Close()
	defer conn1.Close()

	opts0 := &SessionOptions{}
	opts1 := &SessionOptions{}

	opts0.KeyExchangerOptions.PSK = psk0
	opts1.KeyExchangerOptions.PSK = psk1
	opts0.OnInitFuncs = []OnInitFunc{func(sess *Session) { printLogsOfSession(t, !shouldFail, sess) }}
	opts1.OnInitFuncs = []OnInitFunc{func(sess *Session) { printLogsOfSession(t, !shouldFail, sess) }}
	opts0.EnableDebug = true
	opts1.EnableDebug = true

	ctx, cancelFunc := context.WithDeadline(context.Background(), time.Now().Add(time.Second*5))
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
			&testLogger{t, nil},
			opts1,
		)
	}()

	wg.Wait()

	if shouldFail {
		assert.Error(t, err0)
		assert.Error(t, err1)
		assert.Nil(t, keys0)
		assert.Nil(t, keys1)
	} else {
		assert.NoError(t, err0)
		assert.NoError(t, err1)
		assert.NotNil(t, keys0)
		assert.NotNil(t, keys1)
		assert.Equal(t, keys0, keys1)
	}

	testConnIsOpen(t, conn0, conn1)
}

func TestIdentityMutualConfirmationOfIdentityWithoutPSK(t *testing.T) {
	testIdentityMutualConfirmationOfIdentityWithPSKs(t, false, nil, nil)
}

func TestIdentityMutualConfirmationOfIdentityWithPSK(t *testing.T) {
	psk := make([]byte, 64)
	rand.Read(psk)

	testIdentityMutualConfirmationOfIdentityWithPSKs(t, false, psk, psk)
}

func TestIdentityMutualConfirmationOfIdentityWithWrongPSK(t *testing.T) {
	psk0 := make([]byte, 64)
	psk1 := make([]byte, 64)
	rand.Read(psk0)
	copy(psk1, psk0)
	psk0[63] = 0
	psk1[63] = 1

	testIdentityMutualConfirmationOfIdentityWithPSKs(t, true, psk0, psk1)
}
