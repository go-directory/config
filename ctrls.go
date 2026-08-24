package config

import (
	"reflect"
	"strings"

	"github.com/go-directory/dua"
	"github.com/go-directory/ldif"
)

var cnControlsConfigDN = []byte(`cn=controls,cn=config`)

type Controls struct {
	// DN reflects either cn=indices,cn=config, or
	// cn=indices,cn=<friendly dit>,cn=dib,cn=config
	DN      []byte
	Control []Control
}

/*
String returns the string representation of the receiver instance.
*/
func (r Controls) String() string {
	if len(r.DN) == 0 {
		return ``
	}
	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigControls")
	bld.WriteRune(10)
	bld.WriteString("cn: controls")
	bld.WriteRune(10)
	bld.WriteString("description: supportedControl")
	bld.WriteRune(10)
	bld.WriteRune(10)
	for i := 0; i < len(r.Control); i++ {
		bld.WriteString(r.Control[i].String())
		bld.WriteRune(10)
	}

	return bld.String()
}

type Control struct {
	DN   []byte // cn=<oid>,cn=controls,cn=config
	Type []byte `ldap:"cn"`          // controlType (ldap control OID)
	Desc []byte `ldap:"description"` // text description of control
}

func (r Control) String() string {
	if len(r.DN) == 0 || len(r.Type) == 0 {
		return ``
	}

	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigControl")
	bld.WriteRune(10)
	bld.WriteString("cn: ")
	bld.Write(r.Type)
	bld.WriteRune(10)

	if len(r.Desc) > 0 {
		bld.WriteString("description: ")
		bld.Write(r.Desc)
		bld.WriteRune(10)
	}

	return bld.String()
}

func controlsHandler(
	r *Config,
	L *ldif.LDIF,
	E *dua.Entry,
	fv reflect.Value,
	sup string,
) (err error) {

	isTarget := func(a string) bool {
		return strings.HasSuffix(a, sup)
	}

	var ctrls Controls

	makeCtrlEntry := func(entry *ldif.Entry) (ctrl Control) {
		entry.Entry.UnmarshalFunc(&ctrl, func(
			se *dua.Entry,
			ft reflect.StructField,
			sv reflect.Value) error {
			return r.dispatchUnmarshal(L, se, ft, sv)
		})
		return
	}

	for i := 0; i < len(L.Entries) && err == nil; i++ {
		e := L.Entries[i]
		if isTarget(e.Entry.DN) {
			ocs := e.Entry.GetRawAttributeValues("objectClass")
			if bSliceInBSlices([]byte("goDirConfigControls"), ocs) {
				ctrls.DN = []byte(e.Entry.DN)
				continue
			} else if !bSliceInBSlices([]byte("goDirConfigControl"), ocs) {
				continue
			}

			ctrls.Control = append(ctrls.Control, makeCtrlEntry(e))
		}
	}

	if len(ctrls.Control) > 0 && err == nil {
		fv.Set(reflect.ValueOf(ctrls))
	}

	return
}
