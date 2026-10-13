package config

import (
	"reflect"

	"github.com/go-directory/util/ldif"
)

/*
[ldif] type alias.
*/
type (
	LDIF  = ldif.LDIF
	Entry = ldif.GenericEntry
)

/*
ParseLDIF returns an error following an attempt to read the path and filename
and, using [Config.ReadBytes], parse the contents as LDIF. If successful, the
data is marshaled into the receiver instance.

If the file bytes are already acquired, one may instead use the [Config.ReadBytes]
method directly.
*/
func (r *Config) ParseLDIF(path []byte) (err error) {
	spath := string(path)
	if !bHasSfx(path, []byte(`.ldif`)) {
		err = configError("Config '", spath, "' must end in '.ldif'")
		return
	}

	var data []byte
	if data, err = readFile(spath); err == nil {
		err = r.ReadBytes(data)
	}

	return
}

/*
ReadBytes returns an error following an attempt to read the input []byte
instance and parse the contents as LDIF. If successful, the data is marshaled
into the receiver instance.
*/
func (r *Config) ReadBytes(data []byte) (err error) {
	var L *LDIF
	if L, err = ldif.Parse(string(data)); err == nil {
		if cdn := L.Entries[0].DN(); !beq(cdn,cnConfigDN) {
			err = configError("Unexpected config DN '", string(cdn), "'")
			return
		}
	}

	*r = Config{}
	ent := L.Entries[0].(Entry)
	return unmarshalFunc(&ent, r, func(
		e *Entry,
		ft reflect.StructField,
		fv reflect.Value) error {
		return r.dispatchUnmarshal(L, e, ft, fv)
	})
}

func (r *Config) dispatchUnmarshal(
	L *LDIF,
	entry *Entry,
	ft reflect.StructField,
	fv reflect.Value) (err error) {

	if !fv.CanSet() {
		return
	}

	if ft.Name == "DN" && ft.Tag.Get("ldap") == "" {
		fv.SetBytes([]byte(entry.DN()))
		return
	}

	if ft.Type.Kind() == reflect.Struct {
		return r.structUnmarshal(L, entry, fv)
	}

	tag := ft.Tag.Get("ldap")
	if tag == "" {
		return
	}

	tags := splitTags(tag)
	attr := tags[0]
	vals := entry.GetAttributeValues(ad(attr))
	if len(vals) == 0 {
		return
	}
	v := vals[0]

	switch fv.Kind() {
	case reflect.Slice:
		if fv.Type().Elem().Kind() == reflect.Uint8 {
			fv.SetBytes(v)
		}
	case reflect.Int:
		i, _ := pint(string(v), 10, 64)
		fv.SetInt(int64(i))
	case reflect.Uint:
		u, _ := puint(string(v), 10, 64)
		fv.SetUint(u)
	case reflect.Bool:
		fv.SetBool(beqf(v, bTrue))
	case reflect.String:
		fv.SetString(string(v))
	default:
		// handle special field values
		switch fv.Interface().(type) {
		case OctalMode:
			var mode uint64
			mode, err = puint(v.String(), 8, 64)
			if err == nil {
				fv.Set(reflect.ValueOf(OctalMode(mode)))
			}
		}
	}

	return
}

func (r *Config) structUnmarshal(L *LDIF, entry *Entry, fv reflect.Value) (err error) {
	t := fv.Type()

	handlers := map[reflect.Type]func(*LDIF, *Entry, reflect.Value, string) error{
		reflect.TypeOf(Schemata{}):    r.schemataHandler,
		reflect.TypeOf(Limits{}):      r.limitsHandler,
		reflect.TypeOf(ListenerTLS{}): r.listenerTLSHandler,
		reflect.TypeOf(DIB{}):         r.dibHandler,
		reflect.TypeOf(Indices{}):     r.indicesHandler,
		reflect.TypeOf(Controls{}):    r.controlsHandler,
		reflect.TypeOf(Features{}):    r.featuresHandler,
		reflect.TypeOf(Extensions{}):  r.exopHandler,
	}

	if h, ok := handlers[t]; ok {
		err = h(L, entry, fv, entry.DN().String())
	}

	return
}

func (r *Config) schemataHandler(L *LDIF, E *Entry, fv reflect.Value, _ string) error {
	return schemataHandler(L, E, fv, string(cnSchemataConfigDN))
}

func (r *Config) limitsHandler(L *LDIF, E *Entry, fv reflect.Value, _ string) error {
	return limitsHandler(r, L, E, fv, string(cnLimitsConfigDN))
}

func (r *Config) clientTLSHandler(L *LDIF, E *Entry, fv reflect.Value, _ string) error {
	return clientTLSHandler(r, L, E, fv, ``) // dit specific
}

func (r *Config) listenerTLSHandler(L *LDIF, E *Entry, fv reflect.Value, sup string) error {
	return listenerTLSHandler(r, L, E, fv, string(cnTLSConfigDN))
}

func (r *Config) indicesHandler(L *LDIF, E *Entry, fv reflect.Value, _ string) error {
	return indicesHandler(r, L, E, fv, ``)
}

func (r *Config) dibHandler(L *LDIF, E *Entry, fv reflect.Value, _ string) (err error) {
	return dibHandler(r, L, E, fv, ``)
}

func (r *Config) controlsHandler(L *LDIF, E *Entry, fv reflect.Value, _ string) (err error) {
	return controlsHandler(r, L, E, fv, string(cnControlsConfigDN))
}

func (r *Config) featuresHandler(L *LDIF, E *Entry, fv reflect.Value, _ string) (err error) {
	return featuresHandler(r, L, E, fv, string(cnFeaturesConfigDN))
}

func (r *Config) exopHandler(L *LDIF, E *Entry, fv reflect.Value, _ string) (err error) {
	return exopHandler(r, L, E, fv, string(cnExOpConfigDN))
}
