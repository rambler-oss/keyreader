package main

import (
	"strings"

	u "github.com/iavael/goutil"
	"gopkg.in/ldap.v2"
)

// TrustModel type
type TrustModel uint8

const (
	tmFull TrustModel = iota
	tmHost
)

type hostInterface interface {
	inNetGroups([]string) bool
	matchACL(string) bool
}

// Host struct
type Host struct {
	names []string
}

func (h Host) matchACL(acl string) bool {
	return u.MemberOfSlice(acl, h.names)
}

func checkAccess(user string, host hostInterface, entries []*ldap.Entry) bool {
	var (
		tmodel TrustModel
	)

	for _, entry := range entries {
		if tm := entry.GetAttributeValues("trustModel"); len(tm) > 1 {
			logger.Warn("More than 1 trustModel attribute in DN %s, skipping", entry.DN)
			continue
		} else if len(tm) == 1 {
			switch strings.ToLower(tm[0]) {
			case "fullaccess":
				tmodel = tmFull
			case "byhost":
				tmodel = tmHost
			default:
				logger.Warn("Unknown trustmodel \"%s\" in DN %s, assuming \"ByHost\"", tm[0], entry.DN)
			}
		} else {
			tmodel = tmHost
		}

		if tmodel == tmFull {
			logger.Info("Granting access to user %s by trustmodel \"FullAccess\"", user)
			return true
		}

		if tmodel == tmHost && checkByHost(user, entry, host) {
			return true
		}
	}
	return false
}

func checkByHost(user string, entry *ldap.Entry, host hostInterface) bool {
	var netgroups []string
	for _, acl := range entry.GetAttributeValues("accessTo") {
		if strings.HasPrefix(acl, "+") {
			netgroups = append(netgroups, acl[1:])
		} else if host.matchACL(acl) {
			logger.Info("Granting access to user %s by trustmodel \"ByHost\"", user)
			return true
		}
	}
	if host.inNetGroups(netgroups) {
		logger.Info("Granting access to user %s by trustmodel \"ByHost\"", user)
		return true
	}
	return false
}
