package main

import (
	"strings"

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
	matchAcl(string) bool
}

// Host struct
type Host struct {
	name string
}

func (h Host) matchAcl(acl string) bool {
	return h.name == acl
}

func (h Host) inNetGroups(netgroups []string) bool {
	for _, netgroup := range netgroups {
		if nssInNetGr(h.name, netgroup) {
			logger.Info("Found host %s in netgroup %s", h.name, netgroup)
			return true
		}
	}
	return false
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
			}
		} else {
			tmodel = tmHost
		}

		if tmodel == tmFull {
			logger.Info("Granting access to user %s by FullAccess trustmodel", user)
			return true
		}

		if tmodel == tmHost {
			var netgroups []string
			for _, acl := range entry.GetAttributeValues("accessTo") {
				if strings.HasPrefix(acl, "+") {
					netgroups = append(netgroups, acl[1:])
				} else if host.matchAcl(acl) {
					logger.Info("Granting access to user %s by ByHost trustmodel", user)
					return true
				}
			}
			if host.inNetGroups(netgroups) {
				logger.Info("Granting access to user %s by ByHost trustmodel", user)
				return true
			}
		}
	}
	return false
}
