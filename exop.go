package config

import (
	"reflect"
)

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
	bld := &strBuilder{}
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

	bld := &strBuilder{}
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
	L *LDIF,
	E *Entry,
	fv reflect.Value,
	sup string,
) (err error) {

	bsup := []byte(sup)
	isTarget := func(a []byte) bool { return bHasSfx(a, bsup) }

	var exop Extensions

	makeCtrlEntry := func(entry *Entry) (extension Extension) {
		unmarshalFunc(entry, &extension, func(
			se *Entry,
			ft reflect.StructField,
			sv reflect.Value) error {
			return r.dispatchUnmarshal(L, se, ft, sv)
		})
		return
	}

	for i := 0; i < len(L.Entries) && err == nil; i++ {
		e := L.Entries[i]
		ass := e.(Entry)
		dn := e.DN()
		if isTarget(dn) {
			ocs := avs2b(ass.GetAttributeValues(adOC)...)
			if bSliceInBSlices(ocExtentions, ocs) {
				exop.DN = dn
				continue
			} else if !bSliceInBSlices(ocExtention, ocs) {
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
