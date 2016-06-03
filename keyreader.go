package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"strings"

	u "github.com/iavael/goutil"
	"gopkg.in/ldap.v2"
)

type TrustModel uint8

const (
	FULL_ACCESS TrustModel = iota
	BY_HOST
)

const (
	GRP_FILTER = "(&(objectclass=posixGroup)(memberUid=%s)%s)"
	USR_FILTER = "(&(objectclass=posixAccount)(uid=%s)%s)"
	HST_FILTER = "(|(trustmodel=fullaccess)(accessTo=+*)(accessTo=%s))"
)

var (
	config   Config
	logger   *u.Logger
	hostname string
	username string

	ldconn *ldap.Conn
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	if slog, err := syslog.New(syslog.LOG_DAEMON, "keyreader"); err != nil {
		log.Fatalf("Failed to create new syslog: %s", err)
	} else {
		logger = u.NewLogger(u.INFO, slog)
	}

	// Predefine some config options
	config.LdapStartTLS = true

	if err := u.NewConfig(configPath, &config, []int{1}); err != nil {
		logger.Error("Config file error: %s", err)
		os.Exit(10)
	}

	if err := config.Check(); err != nil {
		logger.Error("Config file error: %s", err)
		os.Exit(11)
	}

	if name, err := os.Hostname(); err != nil {
		logger.Error(err.Error())
		os.Exit(12)
	} else {
		hostname = name
	}

	if len(os.Args) < 2 {
		logger.Error("Need user name in argv[1]")
		os.Exit(13)
	}

	if len(os.Args[1]) == 0 {
		logger.Error("Empty username")
		os.Exit(14)
	}
	username = os.Args[1]
}

func main() {
	var (
		hfilter string
	)

	if conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", config.LdapHost, config.LdapPort)); err != nil {
		logger.Error(err.Error())
		os.Exit(15)
	} else {
		defer conn.Close()
		ldconn = conn
	}

	if config.LdapStartTLS {
		if err := ldconn.StartTLS(&tls.Config{InsecureSkipVerify: config.LdapNoTlsVerify}); err != nil {
			logger.Error(err.Error())
			os.Exit(16)
		}
	}

	if err := ldconn.Bind(config.LdapBind, config.LdapPass); err != nil {
		logger.Error(err.Error())
		os.Exit(17)
	}

	hfilter = fmt.Sprintf(HST_FILTER, hostname)

	grpReq := ldap.NewSearchRequest(
		config.LdapGroups,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(GRP_FILTER, username, hfilter),
		[]string{"trustModel", "accessTo"},
		nil,
	)

	if sr, err := ldconn.Search(grpReq); err != nil {
		logger.Error(err.Error())
		os.Exit(18)
	} else {
		if len(sr.Entries) > 0 {
			if checkAccess(sr.Entries) {
				hfilter = ""
			}
		}
	}

	usrReq := ldap.NewSearchRequest(
		config.LdapUsers,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(USR_FILTER, username, hfilter),
		[]string{"trustModel", "accessTo", "sshPublicKey"},
		nil,
	)

	if sr, err := ldconn.Search(usrReq); err != nil {
		logger.Error(err.Error())
		os.Exit(19)
	} else if len(sr.Entries) > 1 {
		logger.Warn("More than 1 user with uid %s, aborting", username)
	} else if len(sr.Entries) > 0 {
		if len(hfilter) != 0 && !checkAccess(sr.Entries) {
			return
		}
		for _, key := range sr.Entries[0].GetAttributeValues("sshPublicKey") {
			fmt.Println(key)
		}
	}

}

func checkAccess(entries []*ldap.Entry) bool {
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
				tmodel = FULL_ACCESS
			case "byhost":
				tmodel = BY_HOST
			}
		} else {
			tmodel = BY_HOST
		}

		if tmodel == FULL_ACCESS {
			logger.Info("Granting access to user %s by FullAccess trustmodel")
			return true
		}

		if tmodel == BY_HOST {
			var netgroups []string
			for _, acl := range entry.GetAttributeValues("accessTo") {
				if strings.HasPrefix(acl, "+") {
					netgroups = append(netgroups, acl[1:])
				} else if acl == hostname {
					logger.Info("Granting access to user %s by ByHost trustmodel")
					return true
				}
			}
			if inNetGroups(ldconn, netgroups) {
				logger.Info("Granting access to user %s by ByHost trustmodel")
				return true
			}
		}
	}
	return false
}
