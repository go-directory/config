package config

import (
	"github.com/go-directory/common"
)

type commonErr = common.Error

func configError(msg ...string) (err commonErr) {
	err = common.ErrorConfig.New(msg...)
	err.SetHeader("config:")
	return
}
