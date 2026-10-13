package config

import (
	"bytes"
	"os"
	"reflect"
	"strconv"
	"strings"
)

var (
	atoi  = strconv.Atoi
	itoa  = strconv.Itoa
	pbool = strconv.ParseBool
	puint = strconv.ParseUint
	pint  = strconv.ParseInt
	fuint = strconv.FormatUint
	fint  = strconv.FormatInt
)

var (
	blc     = bytes.ToLower
	buc     = bytes.ToUpper
	bctns   = bytes.Contains
	bHasSfx = bytes.HasSuffix
	bHasPfx = bytes.HasPrefix
	bidxr   = bytes.IndexRune
	beqf    = bytes.EqualFold
	beq     = bytes.Equal
	bTrimR  = bytes.TrimRight
	bcount  = bytes.Count
)

var (
	readFile = os.ReadFile
	mkdir    = os.Mkdir
)

type (
	strBuilder = strings.Builder
	OctalMode  = os.FileMode
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
	e *Entry,
	i any,
	fn func(entry *Entry, fieldType reflect.StructField, fieldValue reflect.Value) error,
) (err error) {
	// Make sure it's a ptr
	if vo := reflect.ValueOf(i).Kind(); vo != reflect.Pointer {
		err = configError("cannot use '", vo.String(), "', expected pointer to a struct")
		return
	}

	sv, st := reflect.ValueOf(i).Elem(), reflect.TypeOf(i).Elem()
	// Make sure it's pointing to a struct
	if sv.Kind() != reflect.Struct {
		err = configError("expected pointer to a struct, got ", sv.Kind().String())
		return
	}

	for n := 0; n < st.NumField() && err == nil; n++ {
		fv, ft := sv.Field(n), st.Field(n)

		// only consume exported fields
		if ft.PkgPath == "" {
			err = fn(e, ft, fv)
		}
	}

	return
}
