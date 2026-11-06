package config

import (
	"reflect"
)

const (
	reqProhibitAdd      uint8 = 1 << iota // 1
	reqProhibitModify                     // 2
	reqProhibitModifyDN                   // 4
	reqProhibitDel                        // 8
	reqProhibitCompare                    // 16
	reqProhibitSearch                     // 32
)

var reqProhibitedNames = map[uint8]string{
	1:  "add",
	2:  "mod",
	4:  "mdn",
	8:  "del",
	16: "cmp",
	32: "srch",
}

var reqProhibitedBitValues = map[string]uint8{
	"add":  1,
	"mod":  2,
	"mdn":  4,
	"del":  8,
	"cmp":  16,
	"srch": 32,
}

func reqProhibitString(v uint8) string {
	bld := strBuilder{}
	if !(0 < v && v < 64) {
		return `` // bogus or non-actionable bit val
	}
	for i := 1; i < 64; i = i << 1 {
		if uint8(i)&v != 0 {
			bld.WriteString(`configProhibitedRequests: `)
			bld.WriteString(reqProhibitedNames[uint8(i)])
			bld.WriteRune(10)
		}
	}

	return bld.String()
}

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
	DN           []byte              // cn=<friendly dit>,cn=dib,cn=config
	Name         []byte              `ldap:"cn"`              // friendly dit name, e.g.: "example"
	Suffix       []byte              `ldap:"configDITSuffix"` // e.g.: "dc=example,dc=com"
	ParentSuffix []byte              `ldap:"configGlueParentSuffix"`
	Type         int                 `ldap:"configDITType"`
	SubPol       int                 `ldap:"configSubordinatesPolicy"`
	Mode         OctalMode           `ldap:"configDataFileMode"`
	DataDir      []byte              `ldap:"configDataDir"`
	DataFile     []byte              `ldap:"-"`
	SchemaParams []byte              `ldap:"configSchemaParametersDN"`
	Classes      map[string]struct{} `ldap:"-"`

	// zero or more request op types to disallow
	// available types: "add" (1), "mod" (2), "mdn" (4), "del (8), "cmp" (16), "srch" (32)
	// values are shifted, e.g.: 1 << iota
	// operations not listed cannot be disallowed (e.g.: bind).
	Prohibited uint8 `ldap:"configProhibitedRequests"`

	// Whether to publish the suffix via rootDSE namingContexts
	Advertise bool `ldap:"configAdvertiseGlueSuffix"`
	ReadOnly  bool `ldap:"configReadOnly"`
	NoSync    bool `ldap:"configDBNoSync"`
	Monitor   bool `ldap:"configMonitorDIT"`
	Sync      []ReplicationAgreement
	Chaining  []Chaining
	ClientTLS
	Limits
	Indices
}

func (r DIT) ProhibitsAdd() bool      { return r.Prohibited&reqProhibitAdd > 0 }
func (r DIT) ProhibitsModify() bool   { return r.Prohibited&reqProhibitModify > 0 }
func (r DIT) ProhibitsModifyDN() bool { return r.Prohibited&reqProhibitModifyDN > 0 }
func (r DIT) ProhibitsDel() bool      { return r.Prohibited&reqProhibitDel > 0 }
func (r DIT) ProhibitsCompare() bool  { return r.Prohibited&reqProhibitCompare > 0 }
func (r DIT) ProhibitsSearch() bool   { return r.Prohibited&reqProhibitSearch > 0 }

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
	if _, pres := r.Classes[`goDirConfigSubschemaSubentryDIT`]; pres {
		bld.WriteString("objectClass: goDirConfigSubschemaSubentryDIT")
		bld.WriteRune(10)
	} else if _, pres = r.Classes[`goDirConfigMetaSchemaDIT`]; pres {
		bld.WriteString("objectClass: goDirConfigMetaSchemaDIT")
		bld.WriteRune(10)
	}

	bld.WriteString("cn: ")
	bld.Write(r.Name)
	bld.WriteRune(10)
	bld.WriteString("configDITSuffix: ")
	bld.Write(r.Suffix)
	bld.WriteRune(10)
	if len(r.SchemaParams) > 0 {
		bld.WriteString("configSchemaParametersDN: ")
		bld.Write(r.SchemaParams)
		bld.WriteRune(10)
	}

	if len(r.DataDir) > 0 {
		bld.WriteString("configDataDir: ")
		bld.Write(r.DataDir)
		bld.WriteRune(10)
	}

	if r.SubPol > 0 {
		bld.WriteString("configSubordinatesPolicy: ")
		bld.WriteString(itoa(r.SubPol))
		bld.WriteRune(10)
	}

	bld.WriteString("configFileMode: ")
	mode := fuint(uint64(r.Mode), 8)
	for len(mode) < 4 {
		mode = "0" + mode
	}
	bld.WriteString(mode)
	bld.WriteRune(10)

	boo := bFalse
	if r.Mode&0600 == 0 || r.ReadOnly {
		boo = bTrue
	}
	bld.WriteString("configReadOnly: ")
	bld.Write(boo)
	bld.WriteRune(10)

	boo = bFalse
	if r.NoSync {
		boo = bTrue
	}
	bld.WriteString("configDBNoSync: ")
	bld.Write(boo)
	bld.WriteRune(10)

	boo = bFalse
	if r.Monitor {
		boo = bTrue
	}
	bld.WriteString("configMonitorDIT: ")
	bld.Write(boo)
	bld.WriteRune(10)

	if len(r.ParentSuffix) > 0 {
		bld.WriteString("configGlueParentSuffix: ")
		bld.Write(r.ParentSuffix)
		bld.WriteRune(10)

		boo = bFalse
		if r.Advertise {
			boo = bTrue
		}

		bld.WriteString("configAdvertiseGlueSuffix: ")
		bld.Write(boo)
		bld.WriteRune(10)
	}

	bld.WriteString("configDITType: ")
	bld.WriteString(itoa(r.Type))
	bld.WriteRune(10)
	if r.Prohibited > 0 {
		bld.WriteString(reqProhibitString(r.Prohibited))
	}

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
	classes := E.GetAttributeValues([]byte(`objectClass`))
	dit.Classes = make(map[string]struct{})
	for i := 0; i < len(classes); i++ {
		dit.Classes[classes[i].String()] = struct{}{}
	}

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
