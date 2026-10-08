package config

import (
	"bytes"
	"errors"
	"reflect"
	"strings"

	"github.com/go-directory/util/ldif"
)

func bool2str(b bool) string {
	var res string = `FALSE`
	if b {
		res = `TRUE`
	}

	return res
}

func bSliceInBSlices(slice []byte, slices [][]byte, cEM ...bool) (in bool) {
	match := bytes.EqualFold
	if len(cEM) > 0 && cEM[0] {
		// caseExactMatch
		match = bytes.Equal
	}

	for i := 0; i < len(slices) && !in; i++ {
		in = match(slice, slices[i])
	}

	return
}

func splitTags(tagData string) (tags []string) {
	strInSlice := func(s string, sl []string) (in bool) {
		for i := 0; i < len(sl) && !in; i++ {
			in = strings.EqualFold(s, sl[i])
		}
		return
	}

	push := func(val ...string) {
		for i := 0; i < len(val); i++ {
			if !strInSlice(val[i], tags) {
				tags = append(tags, val[i])
			}
		}
	}

	_tags := strings.Split(tagData, `|`)
	for i := 0; i < len(_tags); i++ {
		if tag := _tags[i]; strings.Contains(tag, `;`) {
			t := strings.Split(tag, `;`)
			push(t[0])
			for j := 1; j < len(t); j++ {
				push(t[0] + `;` + t[j])
			}
		} else if strings.HasPrefix(tag, `c-`) {
			push(tag, tag+`;collective`)
		} else {
			push(tag)
		}
	}

	return
}

func unmarshalFunc(
	e *ldif.GenericEntry,
	i any,
	fn func(entry *ldif.GenericEntry, fieldType reflect.StructField, fieldValue reflect.Value) error,
) error {
	// Make sure it's a ptr
	if vo := reflect.ValueOf(i).Kind(); vo != reflect.Pointer {
		return errors.New("ldap: cannot use '" + vo.String() + "', expected pointer to a struct")
	}

	sv, st := reflect.ValueOf(i).Elem(), reflect.TypeOf(i).Elem()
	// Make sure it's pointing to a struct
	if sv.Kind() != reflect.Struct {
		return errors.New("ldap: expected pointer to a struct, got " + sv.Kind().String())
	}

	for n := 0; n < st.NumField(); n++ {
		fv, ft := sv.Field(n), st.Field(n)

		// skip unexported fields
		if ft.PkgPath != "" {
			continue
		}

		if err := fn(e, ft, fv); err != nil {
			return err
		}
	}

	return nil
}
