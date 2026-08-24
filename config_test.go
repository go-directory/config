package config

import (
	_ "embed"
	"testing"
)

//go:embed testdata/dse.ldif
var testDSELDIF []byte

func TestConfig_ReadBytes(t *testing.T) {
	cfg := &Config{}
	if err := cfg.ReadBytes(testDSELDIF); err != nil {
		t.Fatalf("%s failed: %v", t.Name(), err)
	}
	t.Logf("%s", cfg)
	//t.Logf("GLOBAL\n%s\n", C.Indices)
	//t.Logf("LOCAL\n%s", C.DIB.DITs[0].Indices)
	//t.Logf("%s: %#v\n", C.DIB.DITs[0].DN, C.DIB.DITs[0].Limits)

	//t.Logf("[%s] %#v\n", C.Indices.DN, C.Indices.Index)
	//t.Logf("[%s] %#v\n", C.Limits.DN, C.Limits)
	//t.Logf("[%s] %#v\n", C.ListenerTLS.DN, C.ListenerTLS)
	/*
		for i := 0; i < len(C.DIB.DITs); i++ {
			dit := C.DIB.DITs[i]
			t.Logf("dn: %s\n", dit.DN)
			t.Logf("dn: %s\n", dit.Limits.DN)
			t.Logf("sizeLimit: %d", dit.Limits.SizeLimit)
			t.Logf("timeLimit: %d", dit.Limits.TimeLimit)
		}
	*/
}
