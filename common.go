package config

import (
	"github.com/go-directory/common"
)

func configError(msg ...string) (err commonErr) {
	err = common.ErrorConfig.New(msg...)
	err.SetHeader("config:")
	return
}
