package config

import (
	"reflect"
)

/*
Indices facilitates the storage of [Index] slice values. As a whole, this
type serves to define the performance indexing parameters for a specific
portion of a directory.

Instances of this type appear in two contexts: global and local.

A global instance defines indexing parameters for attributes that are used
beyond the bounds of a single directory information tree (for example, "cn"
might be used in "dc=example,dc=com", "cn=monitor", "cn=schema", et al.),
thus it is desirable to only have to configure the parameters once.

A local instance defines indexing parameters for attributes that are
confined to a single naming context, e.g.: "dc=example,dc=com", and appear
nowhere else.
*/
type Indices struct {
	// DN reflects either cn=indices,cn=config, or
	// cn=indices,cn=<friendly dit>,cn=dib,cn=config
	DN    []byte
	Index []Index
}

/*
String returns the string representation of the receiver instance.
*/
func (r Indices) String() string {
	if len(r.DN) == 0 {
		return ``
	}
	bld := &strBuilder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigIndices")
	bld.WriteRune(10)
	bld.WriteString("cn: indices")
	bld.WriteRune(10)
	bld.WriteRune(10)
	for i := 0; i < len(r.Index); i++ {
		bld.WriteString(r.Index[i].String())
		bld.WriteRune(10)
	}

	return bld.String()
}

func (r Indices) isIndexed(at []byte) (is bool) {
	for i := 0; i < len(r.Index) && !is; i++ {
		is = beqf(at, r.Index[i].Attribute)
	}

	return
}

/*
Index implements the slice type of [Indices], and serves to store data
regarding the performance indexing of a single attribute type.
*/
type Index struct {
	DN        []byte // cn=<attr>,cn=indices,cn=<friendly dit>,cn=dib,cn=config
	Attribute []byte `ldap:"cn"`
	Equality  bool   `ldap:"configIndexEquality"`
	Substring bool   `ldap:"configIndexSubstring"`
	Presence  bool   `ldap:"configIndexPresence"`
	Approx    bool   `ldap:"configIndexApprox"`
}

/*
String returns the string representation of the receiver instance.
*/
func (r Index) String() string {
	if len(r.DN) == 0 {
		return ``
	}
	bld := &strBuilder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigIndex")
	bld.WriteRune(10)
	bld.WriteString("cn: ")
	bld.Write(r.Attribute)
	bld.WriteRune(10)

	if r.Equality {
		bld.WriteString("configIndexEquality: TRUE")
		bld.WriteRune(10)
	}

	if r.Substring {
		bld.WriteString("configIndexSubstring: TRUE")
		bld.WriteRune(10)
	}

	if r.Presence {
		bld.WriteString("configIndexPresence: TRUE")
		bld.WriteRune(10)
	}

	if r.Approx {
		bld.WriteString("configIndexApprox: TRUE")
		bld.WriteRune(10)
	}

	return bld.String()
}

func makeIndexEntry(r *Config, L *LDIF, entry *Entry) (idx Index) {
	unmarshalFunc(entry, &idx, func(
		se *Entry,
		ft reflect.StructField,
		sv reflect.Value) error {
		return r.dispatchUnmarshal(L, se, ft, sv)
	})
	return
}

func isIdxTarget(a []byte) bool {
	return bHasSfx(a, cnIndicesConfigDN) ||
		(bctns(a, commaAppend(indicesRDN)) &&
			bHasSfx(a, commaPrepend(cnDIBConfigDN)))
}

func isLocalIndex(c, p []byte) bool {
	return isIdxTarget(c) && bHasSfx(c, p)
}

func isGlobalIndex(c []byte) bool {
	return bHasSfx(c, commaPrepend(cnIndicesConfigDN))
}

func indicesHandler(
	r *Config,
	L *LDIF,
	E *Entry,
	fv reflect.Value,
	_ string,
) (err error) {

	var indices Indices

	isIndexed := func(a []byte, w string) error {
		if indices.isIndexed(a) || r.Indices.isIndexed(a) {
			err = configError("Attribute '", string(a),
				"' is already indexed ", w)
		}
		return err
	}

	edn := E.DN()

	ocs := avs2b(E.GetAttributeValues(adOC)...)
	if bSliceInBSlices(ocIndices, ocs) {
		indices.DN = edn
	}

	if isIdxTarget(edn) {
		for i := 0; i < len(L.Entries) && err == nil; i++ {
			e := L.Entries[i]
			ass := e.(Entry)
			dn := ass.DN()
			ocs := avs2b(ass.GetAttributeValues(adOC)...)
			if bSliceInBSlices(ocIndices, ocs) {
				r.Indices.DN = cnIndicesConfigDN
				continue
			} else if !bSliceInBSlices(ocIndex, ocs) {
				continue
			}
			if isLocalIndex(dn, edn) {
				// LOCAL index
				idx := makeIndexEntry(r, L, &ass)
				if err = isIndexed(idx.Attribute, "LOCALLY"); err == nil {
					indices.Index = append(indices.Index, idx)
				}
			} else if isGlobalIndex(dn) {
				// GLOBAL index
				idx := makeIndexEntry(r, L, &ass)
				if err = isIndexed(idx.Attribute, "GLOBALLY"); err == nil {
					r.Indices.Index = append(r.Indices.Index, idx)
				}
			} else {
				err = configError("Unmatched Index element '", dn.String(), "'")
			}
		}
		if len(indices.Index) > 0 && err == nil {
			fv.Set(reflect.ValueOf(indices))
		}
	}

	return
}
