package secureio

import (
	"testing"

	"github.com/bxcodec/faker"
	"github.com/stretchr/testify/require"
)

func TestMessageFragmentHeadersPool_AcquireMessageFragmentHeaders(t *testing.T) {
	t.Run("negative_isAlreadyBusy", func(t *testing.T) {
		// stupid formal rules of >=90% of coverage by external projects.

		pool := newMessageFragmentHeadersPool()
		hdr := pool.AcquireMessageFragmentHeaders()
		hdr.Release()
		hdr.isBusy = true

		var err interface{}
		func() {
			defer func() {
				err = recover()
			}()

			pool.AcquireMessageFragmentHeaders()
		}()

		require.NotNil(t, err)
	})
}

func TestMessageFragmentHeadersData_Write(t *testing.T) {
	t.Run("negative_tooShort", func(t *testing.T) {
		// stupid formal rules of >=90% of coverage by external projects.
		_, err := (&messageFragmentHeadersData{}).Write([]byte{})
		require.Error(t, err)
	})
}

func TestMessageFragmentHeadersData_Read(t *testing.T) {
	t.Run("negative_tooShort", func(t *testing.T) {
		// stupid formal rules of >=90% of coverage by external projects.
		_, err := (&messageFragmentHeadersData{}).Read([]byte{})
		require.Error(t, err)
	})
}

func TestMessageFragmentHeaders_Reset(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		hdr := messageFragmentHeaders{}
		require.NoError(t, faker.FakeData(&hdr.messageFragmentHeadersData))
		hdr.Reset()
		require.Zero(t, hdr.messageFragmentHeadersData)
	})
}

func TestMessageFragmentHeaders_Release(t *testing.T) {
	t.Run("negative_isNotBusy", func(t *testing.T) {
		// stupid formal rules of >=90% of coverage by external projects.

		pool := newMessageFragmentHeadersPool()
		hdr := pool.AcquireMessageFragmentHeaders()
		hdr.isBusy = false

		var err interface{}
		func() {
			defer func() {
				err = recover()
			}()

			hdr.Release()
		}()

		require.NotNil(t, err)
	})
}
