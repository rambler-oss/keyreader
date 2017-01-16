package main

import (
	"errors"
)

type ConfigV2 struct {
	ConfigBase     `yaml:",inline"`
	LdapServers    []string `yaml:"ldap_servers"`
	LdapIgnoreCert bool     `yaml:"ldap_ignorecert"`
}

func (c *ConfigV2) Check() error {
	switch {
	case len(c.LdapServers) == 0:
		return errors.New("No ldap servers defined")
	}
	return c.ConfigBase.Check()
}

func (c *ConfigV2) GetLdapServers() []string {
	return c.LdapServers
}

func (c *ConfigV2) GetHostnames() []string {
	return []string{}
}

func (c *ConfigV2) GetLdapIgnoreCert() bool {
	return c.LdapIgnoreCert
}

func (c *ConfigV2) FilterByFrom() bool {
	return false
}
