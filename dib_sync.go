package config

import (
	"errors"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-directory/dua"
	"github.com/go-directory/ldif"
	"github.com/go-directory/syntax"
	"github.com/go-directory/syntax/filter"
)

type ReplicationAgreement struct {
	DN       []byte   // cn=<agreement name>,cn=sync,cn=<friendly dit>,cn=dib,cn=config
	Name     []byte   `ldap:"configReplAgreementName"`          // agreement name
	Provider []byte   `ldap:"configReplAgreementProviderURI"`   // ldap://<FQDN>[:<port>]
	Consumer []byte   `ldap:"configReplAgreementConsumerURI"`   // ldap://<FQDN>[:<port>]
	BaseDN   []byte   `ldap:"configReplAgreementBaseDN"`        // root of replicated area
	BindDN   []byte   `ldap:"configReplAgreementSimpleBindDN"`  // simple bind dn
	BindPW   []byte   `ldap:"configReplAgreementSimpleBindPW"`  // simple bind pw
	Cert     []byte   `ldap:"configTLSClientCert"`              // SASL/EXTERNAL X.509 cert
	Key      []byte   `ldap:"configTLSClientKey"`               // SASL/EXTERNAL private key
	Issuer   []byte   `ldap:"configTLSCA"`                      // CA bundle, else use system trust
	Mutual   bool     `ldap:"configTLSClientMutual"`            // client mutual auth
	Mech     []byte   `ldap:"configReplAgreementSASLMechanism"` // SASL mech
	Filter   []byte   `ldap:"configReplAgreementSearchFilter"`  // '(&(objectClass=*))'
	Scope    []byte   `ldap:"configReplAgreementSearchScope"`   // baseObject / singleLevel / wholeSubtree*
	Attrs    [][]byte `ldap:"configReplAgreementAttribute"`     // cn, sn, etc..
	Push     bool     `ldap:"configReplAgreementPush"`          // Push instead of default pull mode
	Tx       bool     `ldap:"configReplAgreementUseTxLog"`      // Use transaction log?
	// TODO: timeout, heartbeat, strict/lax syntax ...
}

func (r ReplicationAgreement) isMTLS() bool {
	return r.Mutual && len(r.Cert) > 0 && len(r.Key) > 0
}

func (r ReplicationAgreement) String() string {
	if len(r.DN) == 0 || len(r.Name) == 0 {
		return ``
	}

	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigReplAgreement")
	bld.WriteRune(10)
	bld.WriteString("cn: ")
	bld.Write(r.Name)
	bld.WriteRune(10)

	if len(r.BaseDN) > 0 {
		bld.WriteString("configReplAgreementBaseDN: ")
		bld.Write(r.BaseDN)
		bld.WriteRune(10)
	}

	if r.Push {
		bld.WriteString("configReplAgreementConsumerURI: ")
		bld.Write(r.Consumer)
		bld.WriteRune(10)
		bld.WriteString("configReplAgreementPush: TRUE")
	} else {
		bld.WriteString("configReplAgreementProviderURI: ")
		bld.Write(r.Provider)
	}
	bld.WriteRune(10)

	if len(r.BindDN) > 0 && len(r.BindPW) > 0 {
		bld.WriteString("configReplAgreementSimpleBindDN: ")
		bld.Write(r.BindDN)
		bld.WriteRune(10)
		bld.WriteString("configReplAgreementSimpleBindPW: ")
		bld.Write(r.BindPW)
		bld.WriteRune(10)
	}

	if len(r.Filter) > 0 {
		bld.WriteString("configReplAgreementSearchFilter: ")
		bld.Write(r.Filter)
		bld.WriteRune(10)
	}

	if L := len(r.Attrs); L > 0 {
		for i := 0; i < L; i++ {
			bld.WriteString("configReplAgreementAttribute: ")
			bld.Write(r.Attrs[i])
			bld.WriteRune(10)
		}
	}

	bld.WriteString("configReplAgreementSearchScope: ")
	switch strings.ToLower(string(r.Scope)) {
	case `base`, `baseobject`:
		bld.WriteString("baseObject")
	case `one`, `onelevel`, `singlelevel`:
		bld.WriteString("singleLevel")
	default:
		bld.WriteString("wholeSubtree")
	}
	bld.WriteRune(10)

	bld.WriteString("configReplAgreementUseTxLog: ")
	bld.WriteString(bool2str(r.Tx))
	bld.WriteRune(10)

	if r.isMTLS() {
		bld.WriteString("configTLSClientCert: ")
		bld.Write(r.Cert)
		bld.WriteRune(10)
		bld.WriteString("configTLSClientKey: ")
		bld.Write(r.Key)
		bld.WriteRune(10)
		bld.WriteString("configTLSClientMutual: TRUE")
		bld.WriteRune(10)
	}

	if len(r.Issuer) > 0 {
		bld.WriteString("configTLSCA: ")
		bld.Write(r.Issuer)
		bld.WriteRune(10)
	}

	return bld.String()
}

func syncHandler(
	L *ldif.LDIF,
	E *dua.Entry,
	fv reflect.Value,
	n string,
) (syncs []ReplicationAgreement, err error) {

	syncSuffix := `,cn=sync,cn=` + n + `,` + string(cnDIBConfigDN)
	for i := 0; i < len(L.Entries) && err == nil; i++ {
		this := L.Entries[i].Entry
		if this.DN != E.DN && strings.HasSuffix(this.DN, syncSuffix) {
			var agree ReplicationAgreement
			if agree, err = buildAgreement(this); err == nil {
				syncs = append(syncs, agree)
			}
		}
	}

	return
}

func buildAgreement(entry *dua.Entry) (agree ReplicationAgreement, err error) {
	ocs := entry.GetRawAttributeValues(`objectClass`)
	if !bSliceInBSlices([]byte(`goDirConfigReplAgreement`), ocs) {
		err = errInvalidSyncClass
		return
	}

	push, _ := strconv.ParseBool(entry.GetAttributeValue(`configReplAgreementPush`))
	mut, _ := strconv.ParseBool(entry.GetAttributeValue(`configTLSClientMutual`))
	usetx, _ := strconv.ParseBool(entry.GetAttributeValue(`configReplAgreementUseTxLog`))

	agree = ReplicationAgreement{
		DN:       []byte(entry.DN),
		Name:     entry.GetRawAttributeValue(`cn`),
		BaseDN:   entry.GetRawAttributeValue(`configReplAgreementBaseDN`),
		Provider: entry.GetRawAttributeValue(`configReplAgreementProviderURI`),
		Consumer: entry.GetRawAttributeValue(`configReplAgreementConsumerURI`),
		BindDN:   entry.GetRawAttributeValue(`configReplAgreementSimpleBindDN`),
		BindPW:   entry.GetRawAttributeValue(`configReplAgreementSimpleBindPW`),
		Mech:     entry.GetRawAttributeValue(`configReplAgreementSASLMechanism`),
		Filter:   entry.GetRawAttributeValue(`configReplAgreementSearchFilter`),
		Attrs:    entry.GetRawAttributeValues(`configReplAgreementAttribute`),
		Mutual:   mut,
		Push:     push,
		Tx:       usetx,
		Cert:     entry.GetRawAttributeValue(`configTLSClientCert`),
		Key:      entry.GetRawAttributeValue(`configTLSClientKey`),
		Issuer:   entry.GetRawAttributeValue(`configTLSCA`),
	}

	err = verifyAgreement(agree)

	return
}

func verifyAgreement(agree ReplicationAgreement) (err error) {
	for _, err := range []error{
		verifyAgreementName(agree),
		verifyAgreementAuth(agree),
		verifyAgreementProvConsURI(agree),
		verifyAgreementSearchParams(agree),
	} {
		if err != nil {
			break
		}
	}

	return
}

func verifyAgreementName(agree ReplicationAgreement) (err error) {
	if len(agree.Name) == 0 {
		err = errMissingSyncName
		return
	}

	aname := string(agree.DN[3:])
	i := strings.IndexRune(aname, ',')
	if i == -1 {
		err = errInvalidSyncDN
		return
	}
	if string(agree.Name) != aname[:i] {
		err = errInvalidSyncRDN
	}

	return
}

func verifyAgreementSearchParams(agree ReplicationAgreement) (err error) {
	_, err = syntax.NewDistinguishedName(agree.BaseDN, false)
	if err != nil || len(agree.BaseDN) == 0 {
		err = errInvalidSyncBaseDN
		return
	}

	if len(agree.Filter) > 0 {
		if _, err = filter.New(agree.Filter); err != nil {
			err = errInvalidSyncFilter
			return
		}
	}

	if len(agree.Scope) > 0 {
		switch strings.ToLower(string(agree.Scope)) {
		case `base`, `baseobject`, `one`, `onelevel`,
			`singlelevel`, `sub`, `subtree`,
			`wholesubtree`:
			// OK
		default:
			err = errInvalidSyncScope
		}

	}

	return
}

func verifyAgreementAuth(agree ReplicationAgreement) (err error) {

	certFound, keyFound := len(agree.Cert) > 0, len(agree.Key) > 0
	sBFound, sPFound := len(agree.BindDN) > 0, len(agree.BindPW) > 0

	switch strings.ToUpper(string(agree.Mech)) {
	case `EXTERNAL`:
		if agree.Mutual {
			if !certFound || !keyFound {
				err = errMissingSyncClientTLSFile
			} else if sBFound || sPFound {
				err = errInvalidSyncClientTLSAuth
			}
		} else {
			err = errMissingSyncTLSMutual
		}
	case `SIMPLE`:
	case `GSSAPI`:
	default:
		if !sBFound || !sPFound {
			err = errInvalidSyncAuth
		} else if agree.Mutual {
			err = errInvalidSyncSimpleMutual
		} else if certFound || keyFound {
			err = errInvalidSimpleTLSFile
		}
	}

	return
}

func verifyAgreementProvConsURI(agree ReplicationAgreement) (err error) {
	plen, clen := len(agree.Provider), len(agree.Consumer)
	if plen > 0 && clen > 0 {
		if agree.Push {
			err = errInvalidSyncURIPush
			return
		}
		err = errInvalidSyncURIPull
	} else if plen == 0 && clen == 0 {
		if agree.Push {
			err = errMissingSyncURIPush
			return
		}
		err = errMissingSyncURIPull
	} else if plen > 0 && agree.Push {
		err = errInvalidSyncURIPush
	} else if clen > 0 && !agree.Push {
		err = errInvalidSyncURIPull
	}

	return
}

var (
	errInvalidSyncURIPush       = errors.New("Cannot use Provider URI in PUSH mode")
	errInvalidSyncURIPull       = errors.New("Cannot use Consumer URI in PULL mode")
	errMissingSyncURIPush       = errors.New("Must specify Consumer URI in PUSH mode")
	errMissingSyncURIPull       = errors.New("Must specify Provider URI in PULL mode")
	errMissingSyncName          = errors.New("Must specify an agreement name using 'cn'")
	errInvalidSyncRDN           = errors.New("cn must match RDN value")
	errInvalidSyncClass         = errors.New("Agreements must use 'goDirConfigReplAgreement' class")
	errInvalidSyncDN            = errors.New("Invalid agreement DN")
	errMissingSyncClientTLSFile = errors.New("Invalid agreement client TLS config; missing cert or key")
	errInvalidSyncClientTLSAuth = errors.New("Invalid agreement client TLS config; simple bind prohibited")
	errMissingSyncTLSMutual     = errors.New("Invalid agreement client TLS config; mutual auth required")
	errInvalidSyncAuth          = errors.New("Invalid agreement auth config; simple bind requires DN and password")
	errInvalidSyncSimpleMutual  = errors.New("Invalid agreement auth config; mutual auth not applicable")
	errInvalidSimpleTLSFile     = errors.New("Invalid agreement auth config; client TLS requires SASL/EXTERNAL")
	errInvalidSyncScope         = errors.New("Invalid agreement search scope")
	errInvalidSyncFilter        = errors.New("Invalid agreement search filter")
	errInvalidSyncBaseDN        = errors.New("Missing or invalid agreement base DN")
)
