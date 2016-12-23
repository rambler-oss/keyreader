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

const (
	grpFilter = "(&(objectclass=posixGroup)(memberUid=%s)%s)"
	usrFilter = "(&(objectclass=posixAccount)(uid=%s)%s)"
	aclFilter = "(|(trustmodel=fullaccess)(accessTo=+*)(accessTo=%s))"
)

var (
	config Config
	logger *u.Logger

	ldconn *ldap.Conn
)

func init() {
	var confpath string

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.StringVar(&confpath, "config", configPath, "Path to config file")
	flag.Parse()

	if slog, err := syslog.New(syslog.LOG_DAEMON, "keyreader"); err != nil {
		log.Fatalf("Failed to create new syslog: %s", err)
	} else {
		logger = u.NewLogger(u.INFO, slog)
	}

	// Predefine some config options
	config.LdapStartTLS = true

	if err := u.NewConfig(confpath, &config, []int{2}); err != nil {
		logger.Error("Config file error: %s", err)
		os.Exit(10)
	}

	if err := config.Check(); err != nil {
		logger.Error("Config file error: %s", err)
		os.Exit(11)
	}
}

func main() {
	var (
		host    Host
		user    string
		hfilter string
	)

	if name, err := os.Hostname(); err != nil {
		logger.Error(err.Error())
		os.Exit(12)
	} else {
		host.name = name
	}

	if len(flag.Args()) < 1 {
		logger.Error("Need user name in argv[1]")
		os.Exit(13)
	}

	if len(flag.Args()[0]) == 0 {
		logger.Error("Empty username")
		os.Exit(14)
	}
	user = flag.Args()[0]

	if code := connLdap(); code != 0 {
		os.Exit(code)
	}

	hfilter = fmt.Sprintf(aclFilter, host.name)

	grpReq := ldap.NewSearchRequest(
		config.LdapGroups,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(grpFilter, user, hfilter),
		[]string{"trustModel", "accessTo"},
		nil,
	)

	if sr, err := ldconn.Search(grpReq); err != nil {
		logger.Error(err.Error())
		os.Exit(18)
	} else {
		if len(sr.Entries) > 0 {
			if checkAccess(user, host, sr.Entries) {
				hfilter = ""
			}
		}
	}

	usrReq := ldap.NewSearchRequest(
		config.LdapUsers,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(usrFilter, user, hfilter),
		[]string{"trustModel", "accessTo", "sshPublicKey"},
		nil,
	)

	if sr, err := ldconn.Search(usrReq); err != nil {
		logger.Error(err.Error())
		os.Exit(19)
	} else if len(sr.Entries) > 1 {
		logger.Warn("More than 1 user with uid %s, aborting", user)
	} else if len(sr.Entries) > 0 {
		if len(hfilter) != 0 && !checkAccess(user, host, sr.Entries) {
			return
		}
		for _, key := range sr.Entries[0].GetAttributeValues("sshPublicKey") {
			fmt.Println(key)
		}
	}
}

func connLdap() int {
	var connected = -1

	for _, server := range config.LdapServers {
		if conn, err := ldap.Dial("tcp", server); err != nil {
			logger.Error(err.Error())
			connected = 15
			continue
		} else {
			if config.LdapStartTLS {
				if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: config.LdapIgnoreCert, ServerName: strings.Split(server, ":")[0]}); err != nil {
					logger.Error(err.Error())
					conn.Close()
					connected = 16
					continue
				}
			}

			if err := conn.Bind(config.LdapBind, config.LdapPass); err != nil {
				logger.Error(err.Error())
				conn.Close()
				connected = 17
				continue
			}
			ldconn = conn
			defer ldconn.Close()
			connected = 0
		}
	}
	return connected
}
