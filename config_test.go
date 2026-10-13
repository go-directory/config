package config

import (
	_ "embed"
	"testing"
)

//go:embed testdata/dse.ldif
var testDSELDIF []byte

func TestConfig_ReadBytes(t *testing.T) {
	cfg := &Config{}
	err := cfg.ReadBytes(testDSELDIF)
	if err != nil {
		t.Fatalf("%s failed: %v", t.Name(), err)
	}

	//} else if err = verify(t, cfg); err != nil {
	//	t.Fatalf("%s failed: %v\n", t.Name(), err)
	//}
	t.Logf("\n%s", cfg) // LDIF output
}

/*
func verify(t *testing.T, r *Config) (err error) {
	seen := make(map[string]struct{})
	expect := map[string]struct{}{
		"frontend": {},
		"state":    {},
		"schema":   {},
		"config":   {},
	}

	for i := 0; i < len(r.DIB.DITs); i++ {
		dit := r.DIB.DITs[i]

		if dit.Name == nil || len(dit.Name) == 0 {
			t.Fatalf("All DITs MUST have a unique alphanumeric name")
		}

		if _, saw := seen[string(dit.Name)]; saw {
			t.Fatalf("DIT %q specified more than once", dit.Name)
		}

		if ownerCanRead := dit.Mode&0400 != 0; !ownerCanRead {
			t.Fatalf("[%s] Owner MUST have read privileges at a minimum", dit.Suffix)
		} else if ownerCanWrite := dit.Mode&0600 != 0; !ownerCanWrite {
			dit.ReadOnly = true
		}

		zeroDIT := dit.Suffix == nil || len(dit.Suffix) == 0 // no suffix
		isFE := beq(dit.Name, []byte(`frontend`))            // name == frontend
		ndd := dit.DataDir == nil || len(dit.DataDir) == 0   // no data dir

		switch dit.Type {
		case 1: // Ephemeral
			if zeroDIT && !isFE {
				t.Fatalf("Only frontend (Root DSE) allows a zero suffix")
			} else if !zeroDIT && isFE {
				t.Fatalf("Frontend requires a zero suffix")
			}

			if !ndd {
				t.Fatalf("Invalid Config.DataDir value for Ephemeral database (must be zero)")
			}

		case 2: // Persistent
			if isFE {
				t.Fatalf("frontend (Root DSE) DIT Type MUST be Ephemeral")
			} else if zeroDIT {
				t.Fatalf("Empty suffix can only serve frontend (Root DSE)")
			}

			if ndd {
				t.Fatalf("Invalid Config.DataDir value for Persistent database")
			}

			dit.DataFile = append(bTrimR(dit.DataDir, `/`), []byte(`/`)...)
			dit.DataFile = append(dit.DataFile, dit.Name...)
			dit.DataFile = append(dit.DataFile, []byte(`/data.db`)...)

			mkdir(string(dit.DataDir)+`/`+string(dit.Name), dit.Mode+0100)

		default:
			t.Fatalf("Invalid DIT Type value; must be Ephemeral(1) or Persistent(2)")
		}

		// register DIT as "seen"
		seen[string(dit.Name)] = struct{}{}
	//	
	//	      t.Logf("name: %q [T:%d]\n", dit.Name, dit.Type)
	//	      t.Logf("dn:   %q\n", dit.Suffix)
	//	      t.Logf("db:   %q\n", dit.DataFile)
	//	      t.Logf("mode: %s\n\n", dit.Mode)
		
	}

	// confirm that certain expected built-in contexts, such as
	// schema, frontend, et al., are indeed present in seen table.
	// If even one is missing, we will panic.
	for k := range expect {
		if _, ok := seen[k]; !ok {
			t.Fatalf("Missing built-in DIT stub for %q", k)
		}
	}

	return
}
*/
