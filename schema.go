package config

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/go-directory/util/ldif"
)

var cnSchemataConfigDN = []byte(`cn=schemata,cn=config`)

type Schemata struct {
	Schema []Schema
}

func (r Schemata) String() string {
	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(cnSchemataConfigDN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigSchemata")
	bld.WriteRune(10)
	bld.WriteString("cn: schemata")
	bld.WriteRune(10)
	bld.WriteRune(10)

	for i := 0; i < len(r.Schema); i++ {
		bld.WriteString(r.Schema[i].String())
		bld.WriteRune(10)
	}

	return bld.String()
}

type Schema struct {
	DN   []byte // cn=<name>,<cnIndicesConfigDN>
	Name []byte `ldap:"cn"`               // what will become "subschemaSubentry: cn=<schemaName>"
	Meta bool   `ldap:"configMetaSchema"` // whether to create the meta form of "cn=<schemaName>"
}

func (r Schema) String() string {
	bld := &strings.Builder{}
	bld.WriteString("dn: ")
	bld.Write(r.DN)
	bld.WriteRune(10)
	bld.WriteString("objectClass: top")
	bld.WriteRune(10)
	bld.WriteString("objectClass: goDirConfigSchema")
	bld.WriteRune(10)
	bld.WriteString("cn: ")
	bld.Write(r.Name)
	bld.WriteRune(10)
	if r.Meta {
		bld.WriteString("configMetaSchema: TRUE")
		bld.WriteRune(10)
	}

	return bld.String()
}

func schemataHandler(L *ldif.LDIF, _ *ldif.GenericEntry, fv reflect.Value, sup string) error {
	var out Schemata
	for _, e := range L.Entries {
		ass := e.(ldif.GenericEntry)
		dn := strings.ToLower(e.DN().String())
		if !strings.HasSuffix(dn, sup) {
			continue
		}

		ocs := avs2b(ass.GetAttributeValues(ad("objectClass"))...)
		if !(bSliceInBSlices([]byte("goDirConfigSchemata"), ocs) ||
			bSliceInBSlices([]byte("goDirConfigSchema"), ocs)) {
			continue
		}

		var sc Schema
		unmarshalFunc(&ass, &sc, func(
			se *ldif.GenericEntry,
			ft reflect.StructField,
			sv reflect.Value) error {
			tag := ft.Tag.Get("ldap")

			if ft.Name == "Name" {
				sc.DN = []byte("cn=" + ass.GetAttributeValue(ad("cn")).String() + "," + sup)
			}

			tags := splitTags(tag)
			attr := tags[0]
			vals := se.GetAttributeValues(ad(attr))
			if len(vals) == 0 {
				return nil
			}
			v := vals[0]

			switch sv.Kind() {
			case reflect.Slice:
				if sv.Type().Elem().Kind() == reflect.Uint8 {
					sv.SetBytes(v)
				}
			case reflect.Bool:
				pb, _ := strconv.ParseBool(string(v))
				sv.SetBool(pb)
			case reflect.Int:
				i, _ := strconv.Atoi(string(v))
				fv.SetInt(int64(i))
			case reflect.String:
				sv.SetString(string(v))
			}
			return nil
		})

		out.Schema = append(out.Schema, sc)
	}

	fv.Set(reflect.ValueOf(out))
	return nil
}
