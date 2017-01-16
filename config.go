package main

import (
	"errors"

	u "github.com/iavael/goutil"
)

type Config interface {
	u.IConfig
	GetHostnames() []string
	GetLdapServers() []string
	FilterByFrom() bool
	GetLdapStartTLS() bool
	GetLdapIgnoreCert() bool
	GetLdapBind() string
	GetLdapPass() string
	GetLdapUsers() string
	GetLdapGroups() string
	GetLdapNetGrs() string
}

type ConfigVer struct {
	Version int `yaml:"version"`
}

// Config file struct
type ConfigBase struct {
	ConfigVer
	LdapStartTLS bool   `yaml:"ldap_starttls"`
	LdapBind     string `yaml:"ldap_bind"`
	LdapPass     string `yaml:"ldap_pass"`
	LdapUsers    string `yaml:"ldap_base_users"`
	LdapGroups   string `yaml:"ldap_base_groups"`
	LdapNetGrs   string `yaml:"ldap_base_netgrs"`
}

// GetVer function returns config file version
func (c *ConfigVer) GetVer() int {
	return c.Version
}

// Check function validates config
func (c *ConfigBase) Check() error {
	switch {
	case len(c.LdapBind) == 0:
		return errors.New("No ldap bind defined")
	case len(c.LdapPass) == 0:
		return errors.New("No ldap password defined")
	case len(c.LdapUsers) == 0:
		return errors.New("No ldap base for users defined")
	case len(c.LdapGroups) == 0:
		return errors.New("No ldap base for posix groups defined")
	case len(c.LdapNetGrs) == 0:
		return errors.New("No ldap base for netgroups defined")
	}
	return nil
}

func (c *ConfigBase) GetLdapStartTLS() bool {
	return c.LdapStartTLS
}

func (c *ConfigBase) GetLdapBind() string {
	return c.LdapBind
}

func (c *ConfigBase) GetLdapPass() string {
	return c.LdapPass
}

func (c *ConfigBase) GetLdapUsers() string {
	return c.LdapUsers
}

func (c *ConfigBase) GetLdapGroups() string {
	return c.LdapGroups
}

func (c *ConfigBase) GetLdapNetGrs() string {
	return c.LdapNetGrs
}

func selectConfig(ver int) u.IConfig {
	switch ver {
	case 1:
		cfg := &ConfigV1{}
		cfg.LdapStartTLS = true
		return cfg
	case 2:
		cfg := &ConfigV2{}
		cfg.LdapStartTLS = true
		return cfg
	case 3:
		cfg := &ConfigV3{}
		cfg.LdapStartTLS = true
		cfg.OnlyWithFrom = true
		return cfg
	}
	return nil
}
