package goutil

import (
	"errors"
	"io/ioutil"
	"strconv"

	"gopkg.in/yaml.v2"
)

// IConfigVer interface for checking version
type IConfigVer interface {
	GetVer() int
}

// IConfig interface for checking version and general config validation
type IConfig interface {
	IConfigVer
	Check() error
}

// NewConfig for parsing and validating YAML config
func NewConfig(file string, c IConfig, vers []int) error {
	var (
		buf []byte
		err error
	)
	if buf, err = ioutil.ReadFile(file); err != nil {
		msg := StrCat("Failed to open config: ", err.Error())
		return errors.New(msg)
	}
	if err = yaml.Unmarshal(buf, c); err != nil {
		msg := StrCat("Invalid config format: ", err.Error())
		return errors.New(msg)
	}
	if !MemberOfSlice(c.GetVer(), vers) {
		msg := StrCat("Unsupported config version ", strconv.Itoa(c.GetVer()), ": need ", JoinInt(vers, ", "))
		return errors.New(msg)
	}
	return c.Check()
}

// NewMultiConfig for parsing and validating YAML config and map to config-dependent structs
func NewMultiConfig(file string, cfgver IConfigVer, cfgmap func(int) IConfig) (IConfig, error) {
	var (
		buf []byte
		err error
		cfg IConfig
	)
	if buf, err = ioutil.ReadFile(file); err != nil {
		msg := StrCat("Failed to open config: ", err.Error())
		return nil, errors.New(msg)
	}
	if err = yaml.Unmarshal(buf, cfgver); err != nil {
		msg := StrCat("Invalid config format: ", err.Error())
		return nil, errors.New(msg)
	}
	cfg = cfgmap(cfgver.GetVer())
	if cfg == nil {
		msg := StrCat("Unsupported config version ", strconv.Itoa(cfgver.GetVer()))
		return nil, errors.New(msg)
	} else if err = yaml.Unmarshal(buf, cfg); err != nil {
		msg := StrCat("Invalid config format: ", err.Error())
		return nil, errors.New(msg)
	}
	return cfg, cfg.Check()
}
