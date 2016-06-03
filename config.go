package main

import (
	"errors"
)

// Config file struct
type Config struct {
	Version         int    `yaml:"version"`
	LdapHost        string `yaml:"ldap_host"`
	LdapPort        int    `yaml:"ldap_port"`
	LdapStartTLS    bool   `yaml:"ldap_starttls"`
	LdapNoTlsVerify bool   `yaml:"ldap_skip_cert_verify"`
	LdapBind        string `yaml:"ldap_bind"`
	LdapPass        string `yaml:"ldap_pass"`
	LdapUsers       string `yaml:"ldap_base_users"`
	LdapGroups      string `yaml:"ldap_base_groups"`
	LdapNetgrs      string `yaml:"ldap_base_netgrs"`
}

// GetVer function returns config file version
func (self *Config) GetVer() int {
	return self.Version
}

// Check function validates config
func (self *Config) Check() error {
	switch {
	case len(self.LdapHost) == 0:
		return errors.New("No ldap host defined")
	case self.LdapPort == 0:
		return errors.New("No ldap port defined")
	case len(self.LdapBind) == 0:
		return errors.New("No ldap bind defined")
	case len(self.LdapPass) == 0:
		return errors.New("No ldap password defined")
	case len(self.LdapUsers) == 0:
		return errors.New("No ldap base for users defined")
	case len(self.LdapGroups) == 0:
		return errors.New("No ldap base for posix groups defined")
	case len(self.LdapNetgrs) == 0:
		return errors.New("No ldap base for netgroups defined")
	}
	return nil
}
