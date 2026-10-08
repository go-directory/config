package config

import (
	"github.com/go-directory/protocol"
)

func ad(x string) protocol.AttributeDescription { return protocol.AttributeDescription(x) }
func av(x string) protocol.AttributeValue       { return protocol.AttributeValue(x) }

func avs2b(av ...protocol.AttributeValue) [][]byte {
	var z [][]byte
	for i := 0; i < len(av); i++ {
		z = append(z, []byte(av[i]))
	}

	return z
}

func b2avs(z ...[]byte) []protocol.AttributeValue {
	var av []protocol.AttributeValue
	for i := 0; i < len(z); i++ {
		av = append(av, protocol.AttributeValue(z[i]))
	}

	return av
}
