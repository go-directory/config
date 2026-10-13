package config

import (
	"reflect"
)

/*
Schemata factilitates the storage of slices of [Schema].
*/
type Schemata struct {
	Schema []Schema
}

/*
String returns the string representation of the receiver instance.
*/
func (r Schemata) String() string {
	bld := &strBuilder{}
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

/*
Schema implements the slice type of [Schemata], and serves as the
storage type for a single schema context, e.g.: "cn=schema".
*/
type Schema struct {
	DN   []byte // cn=<name>,<cnIndicesConfigDN>
	Name []byte `ldap:"cn"`               // what will become "subschemaSubentry: cn=<schemaName>"
	Meta bool   `ldap:"configMetaSchema"` // whether to create the meta form of "cn=<schemaName>"
}

/*
String returns the string representation of the receiver instance.
*/
func (r Schema) String() string {
	bld := &strBuilder{}
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

func schemataHandler(L *LDIF, _ *Entry, fv reflect.Value, sup string) error {
	var out Schemata
	bsup := []byte(sup)
	for _, e := range L.Entries {
		ass := e.(Entry)
		dn := blc(e.DN())
		if !bHasSfx(dn, bsup) {
			continue
		}

		ocs := avs2b(ass.GetAttributeValues(adOC)...)
		if !(bSliceInBSlices(ocSchemata, ocs) ||
			bSliceInBSlices(ocSchema, ocs)) {
			continue
		}

		var sc Schema
		unmarshalFunc(&ass, &sc, func(
			se *Entry,
			ft reflect.StructField,
			sv reflect.Value) error {
			tag := ft.Tag.Get("ldap")

			if ft.Name == "Name" {
				sc.DN = []byte("cn=" + ass.GetAttributeValue(adCN).String() + "," + sup)
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
				pb, _ := pbool(string(v))
				sv.SetBool(pb)
			case reflect.Int:
				i, _ := atoi(string(v))
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
