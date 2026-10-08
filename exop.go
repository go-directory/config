package config

import (
	"reflect"
	"strings"

	"github.com/go-directory/util/ldif"
)

var cnExOpConfigDN = []byte(`cn=exop,cn=config`)

type Extensions struct {
	DN        []byte // cn=exop,cn=config
	Extension []Extension
}

/*
String returns the string representation of the receiver instance.
*/
func (r Extensions) String() string {
	if len(r.DN) == 0 {
		return ``
	}
	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigExtensions")
	bld.WriteRune(10)
	bld.WriteString("cn: exop")
	bld.WriteRune(10)
	bld.WriteString("description: LDAP extended operations")
	bld.WriteRune(10)
	bld.WriteRune(10)
	for i := 0; i < len(r.Extension); i++ {
		bld.WriteString(r.Extension[i].String())
		bld.WriteRune(10)
	}

	return bld.String()
}

type Extension struct {
	DN   []byte // cn=<oid>,cn=exop,cn=config
	Type []byte `ldap:"cn"`          // extension (ldap ExOp OID)
	Desc []byte `ldap:"description"` // text description of exop
}

func (r Extension) String() string {
	if len(r.DN) == 0 || len(r.Type) == 0 {
		return ``
	}

	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigExtension")
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

func exopHandler(
	r *Config,
	L *ldif.LDIF,
	E *ldif.GenericEntry,
	fv reflect.Value,
	sup string,
) (err error) {

	isTarget := func(a string) bool {
		return strings.HasSuffix(a, sup)
	}

	var exop Extensions

	makeCtrlEntry := func(entry *ldif.GenericEntry) (extension Extension) {
		unmarshalFunc(entry, &extension, func(
			se *ldif.GenericEntry,
			ft reflect.StructField,
			sv reflect.Value) error {
			return r.dispatchUnmarshal(L, se, ft, sv)
		})
		return
	}

	for i := 0; i < len(L.Entries) && err == nil; i++ {
		e := L.Entries[i]
		ass := e.(ldif.GenericEntry)
		if isTarget(e.DN().String()) {
			ocs := avs2b(ass.GetAttributeValues(ad("objectClass"))...)
			if bSliceInBSlices([]byte("goDirConfigExtensions"), ocs) {
				exop.DN = []byte(ass.DN())
				continue
			} else if !bSliceInBSlices([]byte("goDirConfigExtension"), ocs) {
				continue
			}

			exop.Extension = append(exop.Extension, makeCtrlEntry(&ass))
		}
	}

	if len(exop.Extension) > 0 && err == nil {
		fv.Set(reflect.ValueOf(exop))
	}

	return
}
