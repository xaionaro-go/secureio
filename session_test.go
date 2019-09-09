package secureio

import (
	"context"
	"testing"
)

func TestSession(t *testing.T) {
	ctx := context.Background()

	identity0, identity1, conn0, conn1 := testPair(t)

	sess0 := identity0.NewSession(ctx, identity1, conn0, &testLogger{"0", t, true}, nil)
	sess1 := identity1.NewSession(ctx, identity0, conn1, &testLogger{"1", t, true}, nil)

	_, err := sess0.Write([]byte(`test`))
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
