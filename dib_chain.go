package config

import (
	"errors"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-directory/dua"
	"github.com/go-directory/ldif"
)

type Chaining struct {
	DN       []byte // cn=<chain name>,cn=chaining,cn=<friendly dit>,cn=dib,cn=config
	Name     []byte `ldap:"cn"`                          // chaining name
	Desc     []byte `ldap:"description"`                 // text description
	Endpoint []byte `ldap:"configChainingEndpointURI"`   // ldap://<FQDN>[:<port>]
	BindDN   []byte `ldap:"configChainingSimpleBindDN"`  // simple bind dn
	BindPW   []byte `ldap:"configChainingSimpleBindPW"`  // simple bind pw
	Mech     []byte `ldap:"configChainingSASLMechanism"` // SASL mech
	Cert     []byte `ldap:"configTLSClientCert"`         // SASL/EXTERNAL X.509 cert
	Key      []byte `ldap:"configTLSClientKey"`          // SASL/EXTERNAL private key
	Issuer   []byte `ldap:"configTLSCA"`                 // CA bundle, else use system trust
	Mutual   bool   `ldap:"configTLSClientMutual"`       // client mutual auth
	// TODO: timeout, heartbeat, strict/lax syntax ...
}

func (r Chaining) String() string {
	if len(r.DN) == 0 || len(r.Name) == 0 {
		return ``
	}

	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigChain")
	bld.WriteRune(10)
	bld.WriteString("cn: ")
	bld.Write(r.Name)
	bld.WriteRune(10)

	if len(r.Desc) > 0 {
		bld.WriteString("description: ")
		bld.Write(r.Desc)
		bld.WriteRune(10)
	}

	bld.WriteString("configChainingEndpointURI: ")
	bld.Write(r.Endpoint)
	bld.WriteRune(10)

	if len(r.BindDN) > 0 && len(r.BindPW) > 0 {
		bld.WriteString("configChainingSimpleBindDN: ")
		bld.Write(r.BindDN)
		bld.WriteRune(10)
		bld.WriteString("configChainingSimpleBindPW: ")
		bld.Write(r.BindPW)
		bld.WriteRune(10)
	}

	if len(r.Mech) > 0 {
		bld.WriteString("configChainingSASLMechanism: ")
		bld.WriteString(strings.ToUpper(string(r.Mech)))
		bld.WriteRune(10)
	}

	if r.Mutual && len(r.Cert) > 0 && len(r.Key) > 0 {
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

func chainingHandler(
	L *ldif.LDIF,
	E *dua.Entry,
	fv reflect.Value,
	n string,
) (chains []Chaining, err error) {

	chainSuffix := `,cn=chaining,cn=` + n + `,` + string(cnDIBConfigDN)
	for i := 0; i < len(L.Entries) && err == nil; i++ {
		this := L.Entries[i].Entry
		if this.DN != E.DN && strings.HasSuffix(this.DN, chainSuffix) {
			var chain Chaining
			if chain, err = buildChaining(this); err == nil {
				chains = append(chains, chain)
			}
		}
	}

	return
}

func buildChaining(entry *dua.Entry) (chain Chaining, err error) {
	ocs := entry.GetRawAttributeValues(`objectClass`)
	if !bSliceInBSlices([]byte(`goDirConfigChain`), ocs) {
		err = errInvalidSyncClass
		return
	}

	mut, _ := strconv.ParseBool(entry.GetAttributeValue(`configTLSClientMutual`))

	chain = Chaining{
		DN:       []byte(entry.DN),
		Name:     entry.GetRawAttributeValue(`cn`),
		Desc:     entry.GetRawAttributeValue(`description`),
		Endpoint: entry.GetRawAttributeValue(`configChainingEndpointURI`),
		BindDN:   entry.GetRawAttributeValue(`configChainingSimpleBindDN`),
		BindPW:   entry.GetRawAttributeValue(`configChainingSimpleBindPW`),
		Mech:     entry.GetRawAttributeValue(`configChainingSASLMechanism`),
		Mutual:   mut,
		Cert:     entry.GetRawAttributeValue(`configTLSClientCert`),
		Key:      entry.GetRawAttributeValue(`configTLSClientKey`),
		Issuer:   entry.GetRawAttributeValue(`configTLSCA`),
	}

	err = verifyChaining(chain)

	return
}

func verifyChaining(chain Chaining) (err error) {
	for _, err := range []error{
		verifyChainingName(chain),
		verifyChainingAuth(chain),
		verifyChainingEndpointURI(chain),
	} {
		if err != nil {
			break
		}
	}

	return
}

func verifyChainingName(chain Chaining) (err error) {
	if len(chain.Name) == 0 {
		err = errMissingChainingName
		return
	}

	aname := string(chain.DN[3:])
	i := strings.IndexRune(aname, ',')
	if i == -1 {
		err = errInvalidChainingDN
		return
	}
	if string(chain.Name) != aname[:i] {
		err = errInvalidChainingRDN
	}

	return
}

func verifyChainingAuth(chain Chaining) (err error) {

	certFound, keyFound := len(chain.Cert) > 0, len(chain.Key) > 0
	sBFound, sPFound := len(chain.BindDN) > 0, len(chain.BindPW) > 0

	switch strings.ToUpper(string(chain.Mech)) {
	case `EXTERNAL`:
		if chain.Mutual {
			if !certFound || !keyFound {
				err = errMissingChainingTLSFile
			} else if sBFound || sPFound {
				err = errInvalidChainingTLSAuth
			}
		} else {
			err = errMissingChainingTLSMutual
		}
	case `SIMPLE`:
	case `GSSAPI`:
	default:
		if !sBFound || !sPFound {
			err = errInvalidSyncAuth
		} else if chain.Mutual {
			err = errInvalidChainingSimpleMutual
		} else if certFound || keyFound {
			err = errInvalidSimpleTLSFile
		}
	}

	return
}

func verifyChainingEndpointURI(chain Chaining) (err error) {
	if len(chain.Endpoint) == 0 {
		err = errInvalidChainingURI
	}

	return
}

var (
	errInvalidChainingURI           = errors.New("Must specify chaining endpoint URI")
	errMissingChainingName          = errors.New("Must specify a chain name using 'cn'")
	errInvalidChainingRDN           = errors.New("cn must match RDN value")
	errInvalidChainingClass         = errors.New("Chains must use 'goDirConfigChain' class")
	errInvalidChainingDN            = errors.New("Invalid chain DN")
	errMissingChainingTLSFile       = errors.New("Invalid chain TLS config; missing cert or key")
	errInvalidChainingTLSAuth       = errors.New("Invalid chain TLS config; simple bind prohibited")
	errMissingChainingTLSMutual     = errors.New("Invalid chain TLS config; mutual auth required")
	errInvalidChainingAuth          = errors.New("Invalid chain config; simple bind requires DN and password")
	errInvalidChainingSimpleMutual  = errors.New("Invalid chain auth config; mutual auth not applicable")
	errInvalidChainingSimpleTLSFile = errors.New("Invalid chain auth config; client TLS requires SASL/EXTERNAL")
)
