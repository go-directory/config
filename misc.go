package config

import (
	"bytes"
	"strings"
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
