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
	debugLog("Search ACL %s in hosts", acl)
	result := u.MemberOfSlice(acl, h.names)
	if result {
		debugLog("ACL %s found in hosts", acl)
	} else {
		debugLog("ACL %s not found in hosts", acl)
	}
	return result
}

func checkAccess(user string, host hostInterface, entries []*ldap.Entry) bool {

	debugLog("Checking ACLs and getting trustModel")
	var (
		tmodel TrustModel
	)

	for _, entry := range entries {
		debugLog("Checking %s", entry.DN)
		if tm := entry.GetAttributeValues("trustModel"); len(tm) > 1 {
			logger.Warn("More than 1 trustModel attribute in DN %s, skipping", entry.DN)
			continue
		} else if len(tm) == 1 {
			switch strings.ToLower(tm[0]) {
			case "fullaccess":
				debugLog("TrustModel is 'FullAccess'")
				tmodel = tmFull
			case "byhost":
				debugLog("TrustModel is 'ByHost'")
				tmodel = tmHost
			default:
				logger.Warn("Unknown trustmodel \"%s\" in DN %s, assuming \"ByHost\"", tm[0], entry.DN)
			}
		} else {
			debugLog("Unknown trustmodel in DN %s, assuming \"ByHost\"", entry.DN)
			tmodel = tmHost
		}

		if tmodel == tmFull {
			logger.Info("Granting access to user %s by trustmodel \"FullAccess\"", user)
			return true
		}

		if tmodel == tmHost {
			if checkByHost(user, entry, host) {
				return true
			}
		}
	}
	debugLog("Access denied: Unknown trustModel")
	return false
}

func checkByHost(user string, entry *ldap.Entry, host hostInterface) bool {
	var netgroups []string
	debugLog("Checking ACL")
	for _, acl := range entry.GetAttributeValues("accessTo") {
		if strings.HasPrefix(acl, "+") {
			netgroups = append(netgroups, acl[1:])
		} else if host.matchACL(acl) {
			logger.Info("Granting access to user %s by trustmodel \"ByHost\"", user)
			return true
		}
	}

	debugLog("Host was not found in ACL")
	if host.inNetGroups(netgroups) {
		logger.Info("Granting access to user %s by trustmodel \"ByHost\"", user)
		return true
	}
	debugLog("Host not found in netgroups, access denied")
	return false
}
