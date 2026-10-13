package config

import (
	"reflect"
)

/*
Controls facilitates the storage of slices of [Control], and represents the
complete manifest of LDAP Controls supported by the DSA.
*/
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
	bld := &strBuilder{}
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

/*
Control implements the slice type of [Controls]. Each instance defines a
single LDAP Control that is supported by the DSA in some manner.
*/
type Control struct {
	DN   []byte // cn=<oid>,cn=controls,cn=config
	Type []byte `ldap:"cn"`          // controlType (ldap control OID)
	Desc []byte `ldap:"description"` // text description of control
}

/*
String returns the string representation of the receiver instance.
*/
func (r Control) String() string {
	if len(r.DN) == 0 || len(r.Type) == 0 {
		return ``
	}

	bld := &strBuilder{}
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
	L *LDIF,
	E *Entry,
	fv reflect.Value,
	sup string,
) (err error) {

	bsup := []byte(sup)
	isTarget := func(a []byte) bool { return bHasSfx(a, bsup) }

	var ctrls Controls

	makeCtrlEntry := func(entry *Entry) (ctrl Control) {
		unmarshalFunc(entry, &ctrl, func(
			se *Entry,
			ft reflect.StructField,
			sv reflect.Value) error {
			return r.dispatchUnmarshal(L, se, ft, sv)
		})
		return
	}

	for i := 0; i < len(L.Entries) && err == nil; i++ {
		e := L.Entries[i]
		dn := e.DN()
		if isTarget(dn) {
			ass := e.(Entry)
			ocs := avs2b(ass.GetAttributeValues(adOC)...)
			if bSliceInBSlices(ocControls, ocs) {
				ctrls.DN = dn
				continue
			} else if !bSliceInBSlices(ocControl, ocs) {
				continue
			}

			ctrls.Control = append(ctrls.Control, makeCtrlEntry(&ass))
		}
	}

	if len(ctrls.Control) > 0 && err == nil {
		fv.Set(reflect.ValueOf(ctrls))
	}

	return
}
