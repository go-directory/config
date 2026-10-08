package config

import (
	"github.com/go-directory/syntax"
)

func ad(x string) syntax.AttributeDescription { return syntax.AttributeDescription(x) }
func av(x string) syntax.AttributeValue       { return syntax.AttributeValue(x) }

func avs2b(av ...syntax.AttributeValue) [][]byte {
	var z [][]byte
	for i := 0; i < len(av); i++ {
		z = append(z, []byte(av[i]))
	}

	return z
}

func b2avs(z ...[]byte) []syntax.AttributeValue {
	var av []syntax.AttributeValue
	for i := 0; i < len(z); i++ {
		av = append(av, syntax.AttributeValue(z[i]))
	}

	return av
}
