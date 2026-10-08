package config

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/go-directory/util/ldif"
)

var cnTLSConfigDN = []byte(`cn=tls,cn=config`)

type ListenerTLS struct {
	DN     []byte
	Cert   []byte `ldap:"configTLSCert"` // path to listener cert
	Key    []byte `ldap:"configTLSKey"`  // path to listener key
	Issuer []byte `ldap:"configTLSCA"`   // path to issuer cert/bundle, else use system trust
}

func (r ListenerTLS) String() string {
	if len(r.DN) == 0 {
		return ``
	}
	bld := &strings.Builder{}
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

type ClientTLS struct {
	DN     []byte
	Cert   []byte `ldap:"configTLSClientCert"`   // path to TLS client certificate
	Key    []byte `ldap:"configTLSClientKey"`    // path to Cert private key
	Issuer []byte `ldap:"configTLSCA"`           // path to issuer cert/bundle, else use system trust
	Mutual bool   `ldap:"configTLSClientMutual"` // mutual auth?
}

func (r ClientTLS) String() string {
	if len(r.DN) == 0 {
		return ``
	}

	bld := &strings.Builder{}
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
	L *ldif.LDIF,
	_ *ldif.GenericEntry,
	fv reflect.Value,
	sup string,
) error {
	for _, e := range L.Entries {
		ass := e.(ldif.GenericEntry)
		dn := e.DN().String()
		if strings.HasPrefix(dn, "cn=tls,") &&
			strings.HasSuffix(dn, ","+string(cnDIBConfigDN)) {
			var tls ClientTLS
			tls.DN = []byte(dn)
			tls.Cert = ass.GetAttributeValue(ad(`configTLSClientCert`))
			tls.Key = ass.GetAttributeValue(ad(`configTLSClientKey`))
			tls.Issuer = ass.GetAttributeValue(ad(`configTLSCA`))
			mut := ass.GetAttributeValue(ad(`configTLSClientMutual`))
			b, _ := strconv.ParseBool(mut.String())
			tls.Mutual = b
			fv.Set(reflect.ValueOf(tls))
			break
		}
	}
	return nil
}

func listenerTLSHandler(
	r *Config,
	L *ldif.LDIF,
	_ *ldif.GenericEntry,
	fv reflect.Value,
	sup string,
) error {
	for _, e := range L.Entries {
		ass := e.(ldif.GenericEntry)
		dn := e.DN().String()
		if strings.EqualFold(dn, string(cnTLSConfigDN)) {
			var tls ListenerTLS
			tls.DN = []byte(dn)
			tls.Cert = ass.GetAttributeValue(ad(`configTLSListenerCert`))
			tls.Key = ass.GetAttributeValue(ad(`configTLSListenerKey`))
			tls.Issuer = ass.GetAttributeValue(ad(`configTLSCA`))
			fv.Set(reflect.ValueOf(tls))
			break
		}
	}
	return nil
}
