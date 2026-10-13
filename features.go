package config

import (
	"reflect"
)

type Features struct {
	// DN reflects either cn=features,cn=config
	DN      []byte
	Feature []Feature
}

/*
String returns the string representation of the receiver instance.
*/
func (r Features) String() string {
	if len(r.DN) == 0 {
		return ``
	}
	bld := &strBuilder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigFeatures")
	bld.WriteRune(10)
	bld.WriteString("cn: features")
	bld.WriteRune(10)
	bld.WriteString("description: supportedFeatures")
	bld.WriteRune(10)
	bld.WriteRune(10)
	for i := 0; i < len(r.Feature); i++ {
		bld.WriteString(r.Feature[i].String())
		bld.WriteRune(10)
	}

	return bld.String()
}

type Feature struct {
	DN   []byte // cn=<oid>,cn=features,cn=config
	Type []byte `ldap:"cn"`          // feature (ldap supportedFeature OID)
	Desc []byte `ldap:"description"` // text description of feature
}

func (r Feature) String() string {
	if len(r.DN) == 0 || len(r.Type) == 0 {
		return ``
	}

	bld := &strBuilder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigFeature")
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

func featuresHandler(
	r *Config,
	L *LDIF,
	E *Entry,
	fv reflect.Value,
	sup string,
) (err error) {

	bsup := []byte(sup)
	isTarget := func(a []byte) bool {
		return bHasSfx(a, bsup)
	}

	var features Features

	makeCtrlEntry := func(entry *Entry) (feature Feature) {
		unmarshalFunc(entry, &feature, func(
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
			if bSliceInBSlices(ocFeatures, ocs) {
				features.DN = dn
				continue
			} else if !bSliceInBSlices(ocFeature, ocs) {
				continue
			}

			features.Feature = append(features.Feature, makeCtrlEntry(&ass))
		}
	}

	if len(features.Feature) > 0 && err == nil {
		fv.Set(reflect.ValueOf(features))
	}

	return
}
