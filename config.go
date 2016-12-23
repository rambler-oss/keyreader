package main

import (
	"errors"
)

// Config file struct
type Config struct {
	Version        int      `yaml:"version"`
	Hostname       string   `yaml:"hostname"`
	OnlyWithFrom   bool     `yaml:"onlywithfrom"`
	LdapServers    []string `yaml:"ldap_servers"`
	LdapStartTLS   bool     `yaml:"ldap_starttls"`
	LdapIgnoreCert bool     `yaml:"ldap_ignorecert"`
	LdapBind       string   `yaml:"ldap_bind"`
	LdapPass       string   `yaml:"ldap_pass"`
	LdapUsers      string   `yaml:"ldap_base_users"`
	LdapGroups     string   `yaml:"ldap_base_groups"`
	LdapNetGrs     string   `yaml:"ldap_base_netgrs"`
}

// GetVer function returns config file version
func (c *Config) GetVer() int {
	return c.Version
}

// Check function validates config
func (c *Config) Check() error {
	switch {
	case len(c.LdapServers) == 0:
		return errors.New("No ldap servers defined")
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
