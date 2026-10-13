package config

import (
	"reflect"
)

/*
ListenerTLS implements a storage type meant to contain the parameters
necessary for the DSA to support inbound TLS-protected requests. Only
one instance of this type exists within the entire [Config] structure.
*/
type ListenerTLS struct {
	DN     []byte
	Cert   []byte `ldap:"configTLSCert"` // path to listener cert
	Key    []byte `ldap:"configTLSKey"`  // path to listener key
	Issuer []byte `ldap:"configTLSCA"`   // path to issuer cert/bundle, else use system trust
	// TODO:
	//  - Supported ciphers
}

/*
String returns the string representation of the receiver instance.
*/
func (r ListenerTLS) String() string {
	if len(r.DN) == 0 {
		return ``
	}

	bld := &strBuilder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigTLS")
	bld.WriteRune(10)
	bld.WriteString("cn: tls")
	bld.WriteRune(10)

	if len(r.Cert) > 0 && len(r.Key) > 0 {
		bld.WriteString("configTLSListenerCert: ")
		bld.Write(r.Cert)
		bld.WriteRune(10)
		bld.WriteString("configTLSListenerKey: ")
		bld.Write(r.Key)
		bld.WriteRune(10)
	}

	if len(r.Issuer) > 0 {
		bld.WriteString("configTLSIssuerCert: ")
		bld.Write(r.Issuer)
		bld.WriteRune(10)
	}
	bld.WriteRune(10)

	return bld.String()
}

/*
ClientTLS implements a storage type meant to contain the parameters
for outbound TLS-protected requests associated with a single [DIT].

This is used for certain distribution-related operations such as
chaining, but is NOT used for replication ([ReplicationAgreement]
contains its own TLS parameters).

Each [DIT] may contain a maximum of one (1) instance of this type.
*/
type ClientTLS struct {
	DN     []byte
	Cert   []byte `ldap:"configTLSClientCert"`   // path to TLS client certificate
	Key    []byte `ldap:"configTLSClientKey"`    // path to Cert private key
	Issuer []byte `ldap:"configTLSCA"`           // path to issuer cert/bundle, else use system trust
	Mutual bool   `ldap:"configTLSClientMutual"` // mutual auth?
}

/*
String returns the string representation of the receiver instance.
*/
func (r ClientTLS) String() string {
	if len(r.DN) == 0 {
		return ``
	}

	bld := &strBuilder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigTLS")
	bld.WriteRune(10)
	bld.WriteString("cn: tls")
	bld.WriteRune(10)

	if len(r.Issuer) > 0 {
		bld.WriteString("configTLSIssuerCert: ")
		bld.Write(r.Issuer)
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

	return bld.String()
}

func clientTLSHandler(
	r *Config,
	L *LDIF,
	_ *Entry,
	fv reflect.Value,
	sup string,
) error {
	for _, e := range L.Entries {
		ass := e.(Entry)
		dn := e.DN()
		if bHasPfx(dn, commaAppend(tlsRDN)) &&
			bHasSfx(dn, cnDIBConfigDN) {
			var tls ClientTLS
			tls.DN = dn
			tls.Cert = ass.GetAttributeValue(adCCert)
			tls.Key = ass.GetAttributeValue(adCKey)
			tls.Issuer = ass.GetAttributeValue(adCA)
			mut := ass.GetAttributeValue(adMutual)
			b, _ := pbool(mut.String())
			tls.Mutual = b
			fv.Set(reflect.ValueOf(tls))
			break
		}
	}
	return nil
}

func listenerTLSHandler(
	r *Config,
	L *LDIF,
	_ *Entry,
	fv reflect.Value,
	sup string,
) error {
	for _, e := range L.Entries {
		ass := e.(Entry)
		dn := e.DN()
		if beqf(dn, cnTLSConfigDN) {
			var tls ListenerTLS
			tls.DN = dn
			tls.Cert = ass.GetAttributeValue(adLCert)
			tls.Key = ass.GetAttributeValue(adLKey)
			tls.Issuer = ass.GetAttributeValue(adCA)
			fv.Set(reflect.ValueOf(tls))
			break
		}
	}
	return nil
}
