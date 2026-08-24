package config

/*
config.go provides types and methods pertaining to an
abstract structure serving as "cn=config".
*/

import (
	"strings"
)

type Config struct {
	DN []byte
	Schemata
	Indices
	Limits
	Controls
	Features
	Extensions
	ListenerTLS
	DIB

	// base values here, e.g.:
	Path []byte `ldap:"configDSEPath"`
}

/*
String returns the string representation of the receiver instance.
*/
func (r Config) String() string {
	if len(r.DN) == 0 || len(r.Path) == 0 {
		return ``
	}

	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfig")
	bld.WriteRune(10)
	bld.WriteString("cn: config")
	bld.WriteRune(10)
	bld.WriteString("configDSEPath: ")
	bld.Write(r.Path)
	bld.WriteRune(10)
	bld.WriteRune(10)
	bld.WriteString(r.Controls.String())
	bld.WriteString(r.Features.String())
	bld.WriteString(r.Extensions.String())
	bld.WriteString(r.Schemata.String())
	bld.WriteString(r.Indices.String())
	bld.WriteString(r.Limits.String())
	bld.WriteString(r.ListenerTLS.String())
	bld.WriteString(r.DIB.String())
	bld.WriteRune(10)

	return bld.String()
}

// cn=config and cn=config subtree literals
var cnConfigDN = []byte(`cn=config`)
