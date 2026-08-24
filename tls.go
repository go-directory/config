package config

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/go-directory/dua"
	"github.com/go-directory/ldif"
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
	_ *dua.Entry,
	fv reflect.Value,
	sup string,
) error {
	for _, e := range L.Entries {
		if strings.HasPrefix(e.Entry.DN, "cn=tls,") &&
			strings.HasSuffix(e.Entry.DN, ","+string(cnDIBConfigDN)) {
			var tls ClientTLS
			tls.DN = []byte(e.Entry.DN)
			tls.Cert = e.Entry.GetRawAttributeValue(`configTLSClientCert`)
			tls.Key = e.Entry.GetRawAttributeValue(`configTLSClientKey`)
			tls.Issuer = e.Entry.GetRawAttributeValue(`configTLSCA`)
			mut := e.Entry.GetAttributeValue(`configTLSClientMutual`)
			b, _ := strconv.ParseBool(mut)
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
	_ *dua.Entry,
	fv reflect.Value,
	sup string,
) error {
	for _, e := range L.Entries {
		if strings.EqualFold(e.Entry.DN, string(cnTLSConfigDN)) {
			var tls ListenerTLS
			tls.DN = []byte(e.Entry.DN)
			tls.Cert = e.Entry.GetRawAttributeValue(`configTLSListenerCert`)
			tls.Key = e.Entry.GetRawAttributeValue(`configTLSListenerKey`)
			tls.Issuer = e.Entry.GetRawAttributeValue(`configTLSCA`)
			fv.Set(reflect.ValueOf(tls))
			break
		}
	}
	return nil
}
