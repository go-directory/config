package config

import (
	"errors"
	"reflect"
	"strings"

	"github.com/go-directory/util/ldif"
)

var cnIndicesConfigDN = []byte(`cn=indices,cn=config`)

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
	bld := &strings.Builder{}
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

func (r Indices) isIndexed(at string) (is bool) {
	for i := 0; i < len(r.Index) && !is; i++ {
		is = strings.EqualFold(at, string(r.Index[i].Attribute))
	}

	return
}

type Index struct {
	DN        []byte // cn=<attr>,cn=indices,cn=<friendly dit>,cn=dib,cn=config
	Attribute []byte `ldap:"cn"`
	Equality  bool   `ldap:"configIndexEquality"`
	Substring bool   `ldap:"configIndexSubstring"`
	Presence  bool   `ldap:"configIndexPresence"`
	Approx    bool   `ldap:"configIndexApprox"`
}

func (r Index) String() string {
	if len(r.DN) == 0 {
		return ``
	}
	bld := &strings.Builder{}
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

func makeIndexEntry(r *Config, L *ldif.LDIF, entry *ldif.GenericEntry) (idx Index) {
	unmarshalFunc(entry, &idx, func(
		se *ldif.GenericEntry,
		ft reflect.StructField,
		sv reflect.Value) error {
		return r.dispatchUnmarshal(L, se, ft, sv)
	})
	return
}

func isIdxTarget(a string) bool {
	return strings.HasSuffix(a, "cn=indices,cn=config") ||
		(strings.Contains(a, "cn=indices,") &&
			strings.HasSuffix(a, ",cn=dib,cn=config"))
}

func isLocalIndex(c, p string) bool {
	return isIdxTarget(c) && strings.HasSuffix(c, p)
}

func isGlobalIndex(c string) bool {
	return strings.HasSuffix(c, ",cn=indices,cn=config")
}

func indicesHandler(
	r *Config,
	L *ldif.LDIF,
	E *ldif.GenericEntry,
	fv reflect.Value,
	_ string,
) (err error) {

	var indices Indices

	isIndexed := func(a, w string) error {
		if indices.isIndexed(a) || r.Indices.isIndexed(a) {
			err = errors.New("Attribute '" + a + "' is already indexed " + w)
		}
		return err
	}

	ocs := avs2b(E.GetAttributeValues(ad("objectClass"))...)
	if bSliceInBSlices([]byte("goDirConfigIndices"), ocs) {
		indices.DN = []byte(E.DN())
	}

	if isIdxTarget(E.DN().String()) {
		for i := 0; i < len(L.Entries) && err == nil; i++ {
			e := L.Entries[i]
			ass := e.(ldif.GenericEntry)
			dn := ass.DN().String()
			ocs := avs2b(ass.GetAttributeValues(ad("objectClass"))...)
			if bSliceInBSlices([]byte("goDirConfigIndices"), ocs) {
				r.Indices.DN = cnIndicesConfigDN
				continue
			} else if !bSliceInBSlices([]byte("goDirConfigIndex"), ocs) {
				continue
			}
			if isLocalIndex(dn, E.DN().String()) {
				// LOCAL index
				idx := makeIndexEntry(r, L, &ass)
				if err = isIndexed(string(idx.Attribute), "LOCALLY"); err == nil {
					indices.Index = append(indices.Index, idx)
				}
			} else if isGlobalIndex(dn) {
				// GLOBAL index
				idx := makeIndexEntry(r, L, &ass)
				if err = isIndexed(string(idx.Attribute), "GLOBALLY"); err == nil {
					r.Indices.Index = append(r.Indices.Index, idx)
				}
			} else {
				err = errors.New("Unmatched Index element '" + dn + "'")
			}
		}
		if len(indices.Index) > 0 && err == nil {
			fv.Set(reflect.ValueOf(indices))
		}
	}

	return
}
