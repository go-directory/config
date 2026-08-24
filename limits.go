package config

import (
	"log"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-directory/dua"
	"github.com/go-directory/ldif"
)

var cnLimitsConfigDN = []byte(`cn=limits,cn=config`)

type Limits struct {
	DN        []byte
	SizeLimit int `ldap:"configSizeLimit"`
	TimeLimit int `ldap:"configTimeLimit"`
}

func (r Limits) String() string {
	if len(r.DN) == 0 {
		return ``
	}
	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigLimits")
	bld.WriteRune(10)
	bld.WriteString("cn: limits")
	bld.WriteRune(10)
	bld.WriteString("configSizeLimit: ")
	bld.WriteString(strconv.Itoa(r.SizeLimit))
	bld.WriteRune(10)
	bld.WriteString("configTimeLimit: ")
	bld.WriteString(strconv.Itoa(r.TimeLimit))
	bld.WriteRune(10)
	bld.WriteRune(10)

	return bld.String()
}

func limitsHandler(
	r *Config,
	L *ldif.LDIF,
	E *dua.Entry,
	fv reflect.Value,
	sup string,
) error {
	isTarget := func(a, c string) bool {
		return strings.EqualFold(a, "cn=limits,cn="+
			c+",cn=dib,cn=config")
	}

	global := sup == "cn=limits,cn=config"
	mm := fv.Interface().(Limits)
	if &mm != nil {
		return nil // already done
	}

	log.Printf("GLOBAL: %t (%q)", global, sup)

	if global {
		var lim Limits
		lim.SizeLimit, _ = strconv.Atoi(E.GetAttributeValue("configSizeLimit"))
		lim.TimeLimit, _ = strconv.Atoi(E.GetAttributeValue("configTimeLimit"))
		lim.DN = []byte(E.DN)
		fv.Set(reflect.ValueOf(lim))
		return nil
	}

	for _, e := range L.Entries {
		if isTarget(e.Entry.DN, sup) {
			log.Printf("2nd path matched: %q", e.Entry.DN)
			var lim Limits
			lim.SizeLimit, _ = strconv.Atoi(e.Entry.GetAttributeValue("configSizeLimit"))
			lim.TimeLimit, _ = strconv.Atoi(e.Entry.GetAttributeValue("configTimeLimit"))
			lim.DN = []byte(e.Entry.DN)
			fv.Set(reflect.ValueOf(lim))
			break
		} else {
			log.Printf("Skip %q", e.Entry.DN)
		}
	}
	return nil
}
