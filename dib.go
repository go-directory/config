package config

import (
	"reflect"
)

/*
DIB facilitates the storage of slices of [DIT] instances. An instance
of this type represents the complete manifest of naming contexts, and
associated configuration parameters, to be honored by the DSA.
*/
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

	bld := &strBuilder{}
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

/*
DIT returns the [DIT] instance bearing the input identifier.

Case is not significant in the matching process.
*/
func (r DIB) DIT(id []byte) (DIT, bool) {
	var dit DIT
	var found bool

	for i := 0; i < len(r.DITs) && !found; i++ {
		if found = beqf(id, r.DITs[i].Name) ||
			beqf(id, r.DITs[i].Suffix); found {
			dit = r.DITs[i]
		}
	}

	return dit, found
}

/*
DIT implements the slice type of [DIB]. Each instance of this type represents
a single naming context and all associated parameters to be honored by the DSA.
*/
type DIT struct {
	DN           []byte    // cn=<friendly dit>,cn=dib,cn=config
	Name         []byte    `ldap:"cn"`              // friendly dit name, e.g.: "example"
	Suffix       []byte    `ldap:"configDITSuffix"` // e.g.: "dc=example,dc=com"
	ParentSuffix []byte    `ldap:"configGlueParentSuffix"`
	Type         int       `ldap:"configDITType"`
	Mode         OctalMode `ldap:"configDataFileMode"`
	DataDir      []byte    `ldap:"configDataDir"`
	DataFile     []byte
	ReadOnly     bool `ldap:"configReadOnly"`
	NoSync       bool `ldap:"configDBNoSync"`
	Sync         []ReplicationAgreement
	Chaining     []Chaining
	ClientTLS
	Limits
	Indices
}

/*
String returns the string representation of the receiver instance.
*/
func (r DIT) String() string {
	if len(r.DN) == 0 {
		return ``
	}
	bld := &strBuilder{}
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
	bld.WriteString(itoa(r.Type))
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

func dibHandler(r *Config, L *LDIF, _ *Entry, fv reflect.Value, _ string) (err error) {
	var dib DIB
	comma := []byte(`,`)
	for i := 0; i < len(L.Entries) && err == nil; i++ {
		this := L.Entries[i]
		dn := this.DN()
		if !bHasSfx(dn, cnDIBConfigDN) {
			continue
		}
		if beqf(dn, cnDIBConfigDN) {
			dib.DN = dn
			continue
		}
		if bcount(dn, comma) == 2 {
			// only descend into immediate children
			// of the "cn=dib,cn=config" context.
			var dit DIT
			ge := this.(Entry)
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
	L *LDIF,
	E *Entry,
	fv reflect.Value,
) (dit DIT, err error) {
	unmarshalFunc(E, &dit, func(
		se *Entry,
		ft reflect.StructField,
		sv reflect.Value) error {
		return r.dispatchUnmarshal(L, se, ft, sv)
	})

	edn := E.DN()
	for _, this := range L.Entries {
		tdn := this.DN()
		if tdn.Equal(edn) || !bHasSfx(tdn, edn) {
			continue
		}

		ass := this.(Entry)

		switch {
		case beqf(tdn, joinDNComps(indicesRDN, edn)):
			sv := reflect.ValueOf(&dit.Indices).Elem()
			r.indicesHandler(L, &ass, sv, tdn.String())
		case beqf(tdn, joinDNComps(limitsRDN, edn)):
			sv := reflect.ValueOf(&dit.Limits).Elem()
			r.limitsHandler(L, &ass, sv, string(dit.Name))
		case bHasPfx(tdn, commaAppend(tlsRDN)):
			sv := reflect.ValueOf(&dit.ClientTLS).Elem()
			r.clientTLSHandler(L, &ass, sv, tdn.String())
		case bHasPfx(tdn, commaAppend(syncRDN)):
			dit.Sync, err = syncHandler(L, &ass, fv, string(dit.Name))
		case bHasPfx(tdn, commaAppend(chainingRDN)):
			dit.Chaining, err = chainingHandler(L, &ass, fv, string(dit.Name))
		}
	}

	return
}
