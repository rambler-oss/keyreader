package main

import (
	"io/ioutil"
	"os"
	"testing"

	u "github.com/iavael/goutil"
	"github.com/stretchr/testify/assert"
)

const (
	cfgv1txt = `
version: 1
ldap_host: ldap.example.com
ldap_port: 389
ldap_skip_cert_verify: false
ldap_bind: cn=user,dc=example,dc=com
ldap_pass: verysecretpassword
ldap_base_users: ou=users,dc=example,dc=com
ldap_base_groups: ou=groups,dc=example,dc=com
ldap_base_netgrs: ou=netgroups,dc=example,dc=com
`
	cfgv2txt = `
version: 2
ldap_servers:
  - ldap1.example.com:389
  - ldap2.example.com:389
ldap_starttls: true
ldap_ignorecert: false
ldap_bind: cn=user,dc=example,dc=com
ldap_pass: verysecretpassword
ldap_base_users: ou=users,dc=example,dc=com
ldap_base_groups: ou=groups,dc=example,dc=com
ldap_base_netgrs: ou=netgroups,dc=example,dc=com
`
	cfgv3txt = `
version: 3
hostnames:
  - cool.host.name
  - cool
ldap_servers:
  - ldap1.example.com:389
  - ldap2.example.com:389
ldap_starttls: true
ldap_ignorecert: false
ldap_bind: cn=user,dc=example,dc=com
ldap_pass: verysecretpassword
ldap_base_users: ou=users,dc=example,dc=com
ldap_base_groups: ou=groups,dc=example,dc=com
ldap_base_netgrs: ou=netgroups,dc=example,dc=com
`
)

func TestConfig(t *testing.T) {
	var (
		assert    = assert.New(t)
		cfgv1path string
		cfgv2path string
		cfgv3path string
	)

	if tmpfile, err := ioutil.TempFile("", "keyreader-test-cfgv1-"); err != nil {
		assert.FailNow("Failed to create tempfile: %s", err)
	} else {
		defer os.Remove(tmpfile.Name())
		if _, err := tmpfile.WriteString(cfgv1txt); err != nil {
			assert.FailNow("Failed to write in tempfile: %s", err)
		} else if err := tmpfile.Close(); err != nil {
			assert.FailNow("Failed to close tempfile: %s", err)
		}
		cfgv1path = tmpfile.Name()
	}

	if tmpfile, err := ioutil.TempFile("", "keyreader-test-cfgv2-"); err != nil {
		assert.FailNow("Failed to create tempfile: %s", err)
	} else {
		defer os.Remove(tmpfile.Name())
		if _, err := tmpfile.WriteString(cfgv2txt); err != nil {
			assert.FailNow("Failed to write in tempfile: %s", err)
		} else if err := tmpfile.Close(); err != nil {
			assert.FailNow("Failed to close tempfile: %s", err)
		}
		cfgv2path = tmpfile.Name()
	}

	if tmpfile, err := ioutil.TempFile("", "keyreader-test-cfgv3-"); err != nil {
		assert.FailNow("Failed to create tempfile: %s", err)
	} else {
		defer os.Remove(tmpfile.Name())
		if _, err := tmpfile.WriteString(cfgv3txt); err != nil {
			assert.FailNow("Failed to write in tempfile: %s", err)
		} else if err := tmpfile.Close(); err != nil {
			assert.FailNow("Failed to close tempfile: %s", err)
		}
		cfgv3path = tmpfile.Name()
	}

	if _, err := u.NewMultiConfig(cfgv1path, &ConfigVer{}, func(ver int) u.IConfig {
		if ver != 1 {
			return nil
		}
		cfg := &ConfigV1{}
		cfg.LdapStartTLS = true
		return cfg
	}); err != nil {
		assert.Fail("Failed config v1 test", err.Error())
	}

	if _, err := u.NewMultiConfig(cfgv2path, &ConfigVer{}, func(ver int) u.IConfig {
		if ver != 2 {
			return nil
		}
		cfg := &ConfigV2{}
		cfg.LdapStartTLS = true
		return cfg
	}); err != nil {
		assert.Fail("Failed config v2 test", err.Error())
	}

	if _, err := u.NewMultiConfig(cfgv3path, &ConfigVer{}, func(ver int) u.IConfig {
		if ver != 3 {
			return nil
		}
		cfg := &ConfigV3{}
		cfg.LdapStartTLS = true
		return cfg
	}); err != nil {
		assert.Fail("Failed config v3 test", err.Error())
	}
}
