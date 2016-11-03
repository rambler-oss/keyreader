package main

import (
	"errors"
)

// Config file struct
type Config struct {
	Version        int      `yaml:"version"`
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
func (self *Config) GetVer() int {
	return self.Version
}

// Check function validates config
func (self *Config) Check() error {
	switch {
	case len(self.LdapServers) == 0:
		return errors.New("No ldap servers defined")
	case len(self.LdapBind) == 0:
		return errors.New("No ldap bind defined")
	case len(self.LdapPass) == 0:
		return errors.New("No ldap password defined")
	case len(self.LdapUsers) == 0:
		return errors.New("No ldap base for users defined")
	case len(self.LdapGroups) == 0:
		return errors.New("No ldap base for posix groups defined")
	case len(self.LdapNetGrs) == 0:
		return errors.New("No ldap base for netgroups defined")
	}
	return nil
}
