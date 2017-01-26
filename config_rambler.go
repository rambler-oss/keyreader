package main

import (
	"errors"
	"os"
	"regexp"
	"strings"

	u "github.com/iavael/goutil"
)

type ConfigRambler struct {
	ConfigBase     `yaml:",inline"`
	OldDomains     []string `yaml:"olddomains"`
	Hostnames      []string `yaml:"hostnames"`
	OnlyWithFrom   bool     `yaml:"onlywithfrom"`
	LdapServers    []string `yaml:"ldap_servers"`
	LdapIgnoreCert bool     `yaml:"ldap_ignorecert"`
}

var oldGroupRegex = regexp.MustCompile(`^([^[:digit:]]+)(?:[[:digit:]]+)(.*)$`)

func (c *ConfigRambler) Check() error {
	switch {
	case len(c.LdapServers) == 0:
		return errors.New("No ldap servers defined")
	}
	return c.ConfigBase.Check()
}

func (c *ConfigRambler) GetLdapServers() []string {
	return c.LdapServers
}

func (c *ConfigRambler) GetOldDomains() []string {
	olddomains := []string{
		"rambler.ru",
		"rambler.tech",
		"afisha.ru",
		"autorambler.ru",
	}
	olddomains = append(olddomains, c.OldDomains...)
	return olddomains
}

func (c *ConfigRambler) GetHostnames() []string {
	hostnames := []string{}
	hostnames = append(hostnames, c.Hostnames...)
	hostnames = append(hostnames, oldGroups()...)
	return hostnames
}

func (c *ConfigRambler) GetLdapIgnoreCert() bool {
	return c.LdapIgnoreCert
}

func (c *ConfigRambler) FilterByFrom() bool {
	return c.OnlyWithFrom
}

func oldGroups() []string {
	var result = []string{}
	if name, err := os.Hostname(); err != nil {
		logger.Error(err.Error())
		os.Exit(12)
	} else {
		var prefix string
		for _, dom := range config.GetOldDomains() {
			logger.Debug("Checking suffix %s for %s", dom, name)
			if strings.HasSuffix(name, dom) {
				prefix = name[:len(name)-len(dom)-1]
				break
			}
		}
		if len(prefix) == 0 {
			return result
		}
		if matches := oldGroupRegex.FindStringSubmatch(prefix); len(matches) == 3 {
			group := u.StrCat(matches[1], matches[2])
			logger.Warn("Using deprecated group %s", group)
			result = append(result, group)
		}
	}
	return result
}
