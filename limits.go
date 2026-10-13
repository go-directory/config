package config

import (
	"reflect"
)

type Limits struct {
	// DN reflects either cn=limits,cn=config, or
	// cn=limits,cn=<friendly dit>,cn=dib,cn=config
	DN        []byte
	SizeLimit uint `ldap:"configSizeLimit"`
	TimeLimit uint `ldap:"configTimeLimit"`
}

/*
String returns the string representation of the receiver instance.
*/
func (r Limits) String() string {
	if len(r.DN) == 0 {
		return ``
	}
	bld := &strBuilder{}
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
	bld.WriteString(fuint(uint64(r.SizeLimit), 10))
	bld.WriteRune(10)
	bld.WriteString("configTimeLimit: ")
	bld.WriteString(fuint(uint64(r.TimeLimit), 10))
	bld.WriteRune(10)
	bld.WriteRune(10)

	return bld.String()
}

func isLimitTarget(a []byte) bool {
	return bHasSfx(a, cnLimitsConfigDN) ||
		(bctns(a, commaAppend(limitsRDN)) &&
			bHasSfx(a, commaPrepend(cnDIBConfigDN)))
}

func isLocalLimit(c, p []byte) bool {
	return isLimitTarget(c) && bHasSfx(c, p)
}

func isGlobalLimit(c []byte, r *Config) bool {
	return beq(c, cnLimitsConfigDN) &&
		len(r.Limits.DN) == 0
}

func limitsHandler(
	r *Config,
	L *LDIF,
	E *Entry,
	fv reflect.Value,
	_ string,
) (err error) {

	var lim Limits

	makeLimits := func(dn []byte, entry Entry) (limits Limits, err error) {
		sstr := entry.GetAttributeValue(adSLimit).String()
		tstr := entry.GetAttributeValue(adTLimit).String()

		var x uint64
		if sstr != "" {
			x, err = puint(sstr, 10, 64)
			if err == nil {
				limits.SizeLimit = uint(x)
			}
		}

		if err == nil {
			if tstr != "" {
				x, err = puint(tstr, 10, 64)
				if err == nil {
					limits.TimeLimit = uint(x)
					fv.Set(reflect.ValueOf(limits))
				}
			}
		}

		limits.DN = dn

		return
	}

	dn := []byte(E.DN())
	if isLocal := isLocalLimit(dn, commaPrepend(cnDIBConfigDN)); isLocal && isLimitTarget(dn) {
		lim, err = makeLimits(dn, *E)
		fv.Set(reflect.ValueOf(lim))
		return
	}

	for i := 0; i < len(L.Entries); i++ {
		e := L.Entries[i].(Entry)
		dn = e.DN()
		if isGlobalLimit(dn, r) {
			lim, err = makeLimits(dn, e)
			fv.Set(reflect.ValueOf(lim))
			break
		}
	}

	return
}
