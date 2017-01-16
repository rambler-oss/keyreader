package main

import (
	"errors"
	"strconv"

	u "github.com/iavael/goutil"
)

type ConfigV1 struct {
	ConfigBase     `yaml:",inline"`
	LdapHost       string `yaml:"ldap_host"`
	LdapPort       int    `yaml:"ldap_port"`
	LdapIgnoreCert bool   `yaml:"ldap_skip_cert_verify"`
}

func (c *ConfigV1) Check() error {
	switch {
	case len(c.LdapHost) == 0:
		return errors.New("No ldap server defined")
	case c.LdapPort == 0:
		return errors.New("No ldap port defined")
	}
	return c.ConfigBase.Check()
}

func (c *ConfigV1) GetLdapServers() []string {
	return []string{u.StrCat(c.LdapHost, ":", strconv.Itoa(c.LdapPort))}
}

func (c *ConfigV1) GetHostnames() []string {
	return []string{}
}

func (c *ConfigV1) GetLdapIgnoreCert() bool {
	return c.LdapIgnoreCert
}

func (c *ConfigV1) FilterByFrom() bool {
	return false
}
