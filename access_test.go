package main

import (
	"testing"

	u "github.com/iavael/goutil"
	"github.com/stretchr/testify/assert"
	"gopkg.in/ldap.v2"
)

type HostTest struct {
	hostname string
}

func (ht HostTest) inNetGroups(_ []string) bool {
	return false
}

func (ht HostTest) matchACL(acl string) bool {
	return ht.hostname == acl
}

func TestAccess(t *testing.T) {
	var (
		assert = assert.New(t)
		test   *ldap.Entry
	)

	logger = u.NewLogger(u.FATAL, nil)

	test = ldap.NewEntry("cn=test", map[string][]string{
		"trustModel": {"fullAccess"},
	})
	assert.True(checkAccess("user", HostTest{"example.com"}, []*ldap.Entry{test}))

	test = ldap.NewEntry("cn=test", map[string][]string{
		"trustModel": {"byHost"},
	})
	assert.False(checkAccess("user", HostTest{"example.com"}, []*ldap.Entry{test}))

	test = ldap.NewEntry("cn=test", map[string][]string{})
	assert.False(checkAccess("user", HostTest{"example.com"}, []*ldap.Entry{test}))

	test = ldap.NewEntry("cn=test", map[string][]string{
		"trustModel": {"byHost"},
		"accessTo":   {"example.com"},
	})
	assert.True(checkAccess("user", HostTest{"example.com"}, []*ldap.Entry{test}))

	test = ldap.NewEntry("cn=test", map[string][]string{
		"trustModel": {"byHost"},
		"accessTo":   {"example.net"},
	})
	assert.False(checkAccess("user", HostTest{"example.com"}, []*ldap.Entry{test}))
}
