package main

import (
	"errors"
)

type ConfigV3 struct {
	ConfigBase     `yaml:",inline"`
	Hostnames      []string `yaml:"hostnames"`
	OnlyWithFrom   bool     `yaml:"onlywithfrom"`
	LdapServers    []string `yaml:"ldap_servers"`
	LdapIgnoreCert bool     `yaml:"ldap_ignorecert"`
}

func (c *ConfigV3) Check() error {
	switch {
	case len(c.LdapServers) == 0:
		return errors.New("No ldap servers defined")
	}
	return c.ConfigBase.Check()
}

func (c *ConfigV3) GetLdapServers() []string {
	return c.LdapServers
}

func (c *ConfigV3) GetHostnames() []string {
	return c.Hostnames
}

func (c *ConfigV3) GetLdapIgnoreCert() bool {
	return c.LdapIgnoreCert
}

func (c *ConfigV3) FilterByFrom() bool {
	return c.OnlyWithFrom
}
