package config

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-directory/dua"
	"github.com/go-directory/ldif"
)

func (r *Config) ParseLDIF(path string) (err error) {
	if !strings.HasSuffix(path, `.ldif`) {
		err = errors.New("Config '" + path + "' must end in '.ldif'")
		return
	}

	var data []byte
	if data, err = os.ReadFile(path); err == nil {
		err = r.ReadBytes(data)
	}

	return
}

func (r *Config) ReadBytes(data []byte) (err error) {
	var L *ldif.LDIF
	if L, err = ldif.Parse(string(data)); err == nil {
		if cdn := L.Entries[0].Entry.DN; cdn != string(cnConfigDN) {
			err = errors.New("Unexpected config DN '" + cdn + "'")
			return
		}
	}

	*r = Config{}
	return L.Entries[0].Entry.UnmarshalFunc(r, func(
		e *dua.Entry,
		ft reflect.StructField,
		fv reflect.Value) error {
		return r.dispatchUnmarshal(L, e, ft, fv)
	})
}

func (r *Config) dispatchUnmarshal(
	L *ldif.LDIF,
	entry *dua.Entry,
	ft reflect.StructField,
	fv reflect.Value) error {

	if !fv.CanSet() {
		return nil
	}

	if ft.Name == "DN" && ft.Tag.Get("ldap") == "" {
		fv.SetBytes([]byte(entry.DN))
		return nil
	}

	if ft.Type.Kind() == reflect.Struct {
		return r.structUnmarshal(L, entry, fv)
	}

	tag := ft.Tag.Get("ldap")
	if tag == "" {
		return nil
	}

	tags := splitTags(tag)
	attr := tags[0]
	vals := entry.GetRawAttributeValues(attr)
	if len(vals) == 0 {
		return nil
	}
	v := vals[0]

	switch fv.Kind() {
	case reflect.Slice:
		if fv.Type().Elem().Kind() == reflect.Uint8 {
			fv.SetBytes(v)
		}
	case reflect.Int:
		i, _ := strconv.Atoi(string(v))
		fv.SetInt(int64(i))
	case reflect.Bool:
		fv.SetBool(bytes.EqualFold(v, []byte("TRUE")))
	case reflect.String:
		fv.SetString(string(v))
	}

	return nil
}

func (r *Config) structUnmarshal(L *ldif.LDIF, entry *dua.Entry, fv reflect.Value) error {
	t := fv.Type()

	handlers := map[reflect.Type]func(*ldif.LDIF, *dua.Entry, reflect.Value, string) error{
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
		return h(L, entry, fv, entry.DN)
	}

	return nil
}

func (r *Config) schemataHandler(L *ldif.LDIF, E *dua.Entry, fv reflect.Value, _ string) error {
	return schemataHandler(L, E, fv, string(cnSchemataConfigDN))
}

func (r *Config) limitsHandler(L *ldif.LDIF, E *dua.Entry, fv reflect.Value, _ string) error {
	return limitsHandler(r, L, E, fv, string(cnLimitsConfigDN))
}

func (r *Config) clientTLSHandler(L *ldif.LDIF, E *dua.Entry, fv reflect.Value, _ string) error {
	return clientTLSHandler(r, L, E, fv, ``) // dit specific
}

func (r *Config) listenerTLSHandler(L *ldif.LDIF, E *dua.Entry, fv reflect.Value, sup string) error {
	return listenerTLSHandler(r, L, E, fv, string(cnTLSConfigDN))
}

func (r *Config) indicesHandler(L *ldif.LDIF, E *dua.Entry, fv reflect.Value, _ string) error {
	return indicesHandler(r, L, E, fv, ``)
}

func (r *Config) dibHandler(L *ldif.LDIF, E *dua.Entry, fv reflect.Value, _ string) (err error) {
	return dibHandler(r, L, E, fv, ``)
}

func (r *Config) controlsHandler(L *ldif.LDIF, E *dua.Entry, fv reflect.Value, _ string) (err error) {
	return controlsHandler(r, L, E, fv, string(cnControlsConfigDN))
}

func (r *Config) featuresHandler(L *ldif.LDIF, E *dua.Entry, fv reflect.Value, _ string) (err error) {
	return featuresHandler(r, L, E, fv, string(cnFeaturesConfigDN))
}

func (r *Config) exopHandler(L *ldif.LDIF, E *dua.Entry, fv reflect.Value, _ string) (err error) {
	return exopHandler(r, L, E, fv, string(cnExOpConfigDN))
}
