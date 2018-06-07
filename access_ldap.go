// +build ldap,!libc !cgo,!libc freebsd,!libc

package main

import (
	"os"
	"regexp"

	"gopkg.in/ldap.v2"
)

const (
	netgrMember = "nisNetgroupTriple"
	netgrChild  = "memberNisNetgroup"
	tripleElem  = `(|\-|[[:alnum:]](?:[[:alnum:]\-\.]*?[[:alnum:]])?)`
	netgrTriple = `^\(` + tripleElem + `,` + tripleElem + `,` + tripleElem + `\)$`
)

var (
	ngMemberRegex = regexp.MustCompile(netgrTriple)
)

func (h Host) inNetGroups(netgroups []string) bool {
	var (
		looptest = map[string]bool{}
		nextgrps []string
	)

	nextgrps = netgroups
	for _, grp := range nextgrps {
		looptest[grp] = true
	}

	for len(nextgrps) > 0 {
		var netgr string
		netgr, nextgrps = nextgrps[0], nextgrps[1:]
		looptest[netgr] = true
		netGroupReq := ldap.NewSearchRequest(
			config.GetLdapNetGrs(),
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			strCat("(cn=", netgr, ")"),
			[]string{netgrMember, netgrChild},
			nil,
		)
		if sr, err := ldconn.Search(netGroupReq); err != nil {
			logger.Error(err.Error())
			os.Exit(20)
		} else {
			for _, entry := range sr.Entries {
				if matchHosts(netgr, entry.GetAttributeValues(netgrMember), h.names) {
					return true
				}
				newchildren := filterLoops(netgr, entry.GetAttributeValues(netgrChild), looptest)
				nextgrps = append(nextgrps, newchildren...)
			}
		}
	}
	return false
}

func filterLoops(netgr string, children []string, looptest map[string]bool) (res []string) {
	for _, child := range children {
		if _, ok := looptest[child]; !ok {
			logger.Warn("Detected loop on netgroup %s", netgr)
			continue
		}
		res = append(res, child)
	}
	return
}

func matchHosts(netgr string, triples []string, hosts []string) bool {
	if triples == nil {
		return false
	}
	for _, triple := range triples {
		if matches := ngMemberRegex.FindStringSubmatch(triple); len(matches) == 0 {
			logger.Warn("Invalid %s triple in netgroup %s", triple, netgr)
			continue
		} else {
			for _, host := range hosts {
				if matches[1] == "-" {
					logger.Warn("Undefined host in triple %s of netgroup %s", triple, netgr)
					continue
				} else if matches[1] == "" {
					logger.Warn("Wildcard host in triple %s of netgroup %s", triple, netgr)
					continue
				} else if matches[1] == host {
					logger.Info("Found host %s in netgroup %s", host, netgr)
					return true
				}
				logger.Debug("No host %s in netgroup %s", host, netgr)
			}
		}
	}
	return false
}
