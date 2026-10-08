package config

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/go-directory/util/ldif"
)

var cnDIBConfigDN = []byte(`cn=dib,cn=config`)

type DIB struct {
	DN   []byte // cn=dib,cn=config
	DITs []DIT
}

/*
String returns the string representation of the receiver instance.
*/
func (r DIB) String() string {
	if len(r.DN) == 0 {
		return ``
	}

	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigDIB")
	bld.WriteRune(10)
	bld.WriteString("cn: dib")
	bld.WriteRune(10)
	bld.WriteRune(10)
	for i := 0; i < len(r.DITs); i++ {
		bld.WriteString(r.DITs[i].String())
	}

	return bld.String()
}

type DIT struct {
	DN           []byte // cn=<friendly dit>,cn=dib,cn=config
	Name         []byte `ldap:"cn"` // friendly dit name, e.g.: "example"
	Suffix       []byte `ldap:"configDITSuffix"`
	ParentSuffix []byte `ldap:"configGlueParentSuffix"`
	Type         int    `ldap:"configDITType"`
	Sync         []ReplicationAgreement
	Chaining     []Chaining
	ClientTLS
	Limits
	Indices
}

func (r DIT) String() string {
	if len(r.DN) == 0 {
		return ``
	}
	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigDIT")
	bld.WriteRune(10)
	bld.WriteString("cn: ")
	bld.Write(r.Name)
	bld.WriteRune(10)
	bld.WriteString("configDITSuffix: ")
	bld.Write(r.Suffix)
	bld.WriteRune(10)
	if len(r.ParentSuffix) > 0 {
		bld.WriteString("configGlueParentSuffix: ")
		bld.Write(r.ParentSuffix)
		bld.WriteRune(10)
	}
	bld.WriteString("configDITType: ")
	bld.WriteString(strconv.Itoa(r.Type))
	bld.WriteRune(10)

	ct := &ClientTLS{}
	if &r.ClientTLS != ct {
		bld.WriteRune(10)
		bld.WriteString(r.ClientTLS.String())
	}

	mt := &Limits{}
	if &r.Limits != mt {
		bld.WriteString(r.Limits.String())
	}

	idx := &Indices{}
	if &r.Indices != idx {
		bld.WriteString(r.Indices.String())
	}

	if L := len(r.Sync); L > 0 {
		bld.WriteString("dn: cn=sync,cn=")
		bld.Write(r.Name)
		bld.WriteRune(',')
		bld.Write(cnDIBConfigDN)
		bld.WriteRune(10)
		bld.WriteString("objectClass: top")
		bld.WriteRune(10)
		bld.WriteString("objectClass: goDirConfigReplAgreements")
		bld.WriteRune(10)
		bld.WriteString("cn: sync")
		bld.WriteRune(10)
		bld.WriteRune(10)
		for i := 0; i < L; i++ {
			bld.WriteString(r.Sync[i].String())
			bld.WriteRune(10)
		}
	}

	if L := len(r.Chaining); L > 0 {
		bld.WriteString("dn: cn=chaining,cn=")
		bld.Write(r.Name)
		bld.WriteRune(',')
		bld.Write(cnDIBConfigDN)
		bld.WriteRune(10)
		bld.WriteString("objectClass: top")
		bld.WriteRune(10)
		bld.WriteString("objectClass: goDirConfigChains")
		bld.WriteRune(10)
		bld.WriteString("cn: chaining")
		bld.WriteRune(10)
		bld.WriteRune(10)
		for i := 0; i < L; i++ {
			bld.WriteString(r.Chaining[i].String())
			bld.WriteRune(10)
		}
	}

	return bld.String()
}

func dibHandler(r *Config, L *ldif.LDIF, _ *ldif.GenericEntry, fv reflect.Value, _ string) (err error) {
	var dib DIB
	sup := string(cnDIBConfigDN)

	for i := 0; i < len(L.Entries) && err == nil; i++ {
		this := L.Entries[i]
		dn := string(this.DN())
		if !strings.HasSuffix(dn, sup) {
			continue
		}
		if strings.EqualFold(dn, sup) {
			dib.DN = []byte(dn)
			continue
		}
		if strings.Count(dn, ",") == 2 {
			// only descend into immediate children
			// of the "cn=dib,cn=config" context.
			var dit DIT
			ge := this.(ldif.GenericEntry)
			if dit, err = ditHandler(r, L, &ge, fv); err == nil {
				dib.DITs = append(dib.DITs, dit)
			}
		}
	}

	fv.Set(reflect.ValueOf(dib))

	return
}

func ditHandler(
	r *Config,
	L *ldif.LDIF,
	E *ldif.GenericEntry,
	fv reflect.Value,
) (dit DIT, err error) {
	unmarshalFunc(E, &dit, func(
		se *ldif.GenericEntry,
		ft reflect.StructField,
		sv reflect.Value) error {
		return r.dispatchUnmarshal(L, se, ft, sv)
	})

	for _, this := range L.Entries {
		tdn := this.DN().String()
		if tdn == E.DN().String() || !strings.HasSuffix(tdn, E.DN().String()) {
			continue
		}

		ass := this.(ldif.GenericEntry)

		switch {
		case strings.EqualFold(tdn, "cn=indices,"+E.DN().String()):
			sv := reflect.ValueOf(&dit.Indices).Elem()
			r.indicesHandler(L, &ass, sv, tdn)
		case strings.EqualFold(tdn, "cn=limits,"+E.DN().String()):
			sv := reflect.ValueOf(&dit.Limits).Elem()
			r.limitsHandler(L, &ass, sv, string(dit.Name))
		case strings.HasPrefix(tdn, "cn=tls,"):
			sv := reflect.ValueOf(&dit.ClientTLS).Elem()
			r.clientTLSHandler(L, &ass, sv, tdn)
		case strings.HasPrefix(tdn, "cn=sync,"):
			dit.Sync, err = syncHandler(L, &ass, fv, string(dit.Name))
		case strings.HasPrefix(tdn, "cn=chaining,"):
			dit.Chaining, err = chainingHandler(L, &ass, fv, string(dit.Name))
		}
	}

	return
}
