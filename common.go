package config

import (
	"github.com/go-directory/common"
)

func configError(msg ...string) error {
	m := append([]string{"Config error: "}, msg...)
	return common.ErrorConfig.New(m...)
}
