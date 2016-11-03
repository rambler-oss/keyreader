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

func (_ HostTest) inNetGroups(_ []string) bool {
	return false
}

func (ht HostTest) matchAcl(acl string) bool {
	return ht.hostname == acl
}

func TestAccess(t *testing.T) {
	var (
		test   *ldap.Entry
		assert = assert.New(t)
	)

	logger = u.NewLogger(u.FATAL, nil)

	test = ldap.NewEntry("cn=test", map[string][]string{
		"trustModel": []string{"fullAccess"},
	})
	assert.True(checkAccess("user", HostTest{"example.com"}, []*ldap.Entry{test}))

	test = ldap.NewEntry("cn=test", map[string][]string{
		"trustModel": []string{"byHost"},
	})
	assert.False(checkAccess("user", HostTest{"example.com"}, []*ldap.Entry{test}))

	test = ldap.NewEntry("cn=test", map[string][]string{})
	assert.False(checkAccess("user", HostTest{"example.com"}, []*ldap.Entry{test}))

	test = ldap.NewEntry("cn=test", map[string][]string{
		"trustModel": []string{"byHost"},
		"accessTo": []string{
			"example.com",
		},
	})
	assert.True(checkAccess("user", HostTest{"example.com"}, []*ldap.Entry{test}))

	test = ldap.NewEntry("cn=test", map[string][]string{
		"trustModel": []string{"byHost"},
		"accessTo": []string{
			"example.net",
		},
	})
	assert.False(checkAccess("user", HostTest{"example.com"}, []*ldap.Entry{test}))
}