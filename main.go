package main

import (
	"crypto/tls"
	"flag"
	"log"
	"log/syslog"
	"os"
	"strings"

	u "github.com/iavael/goutil"
	"gopkg.in/ldap.v2"
)

var (
	confpath string

	config Config
	logger *u.Logger

	ldconn ldap.Client
)

func init() {
	flag.Usage = func() {
		os.Stderr.WriteString("Usage of ")
		os.Stderr.WriteString(os.Args[0])
		os.Stderr.WriteString(":\n")
		flag.PrintDefaults()
	}

	flag.StringVar(&confpath, "config", configPath, "Path to config file")
	flag.Parse()

	// Predefine some config options
	config.LdapStartTLS = true
}

func main() {
	var (
		host Host
		user string
	)

	if slog, err := syslog.New(syslog.LOG_DAEMON, "keyreader"); err != nil {
		log.Fatalf("Failed to create new syslog: %s", err)
	} else {
		logger = u.NewLogger(u.INFO, slog)
	}

	if err := u.NewConfig(confpath, &config, []int{2}); err != nil {
		logger.Error("Config file error: %s", err)
		os.Exit(10)
	}

	if err := config.Check(); err != nil {
		logger.Error("Config file error: %s", err)
		os.Exit(11)
	}

	if len(config.Hostname) != 0 {
		host.name = config.Hostname
	} else if name, err := os.Hostname(); err != nil {
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

	if conn, code := connLdap(); code != 0 {
		os.Exit(code)
	} else {
		ldconn = conn
		defer ldconn.Close()
	}

	for _, key := range checkUser(user, &host) {
		os.Stdout.WriteString(key)
		os.Stdout.WriteString("\n")
	}
}

func checkGroup(user string, host *Host) bool {
	grpReq := ldap.NewSearchRequest(
		config.LdapGroups,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		grpFilter(user, host.name),
		[]string{"trustModel", "accessTo"},
		nil,
	)

	if sr, err := ldconn.Search(grpReq); err != nil {
		logger.Error(err.Error())
		os.Exit(18)
	} else {
		if len(sr.Entries) > 0 {
			if !checkAccess(user, host, sr.Entries) {
				// Just get keys, don't check user's accessTo
				return true
			}
		}
	}
	return false
}

func checkUser(user string, host *Host) []string {
	// Don't check user's acl if their group has permission
	noUsrAcl := checkGroup(user, host)
	usrReq := ldap.NewSearchRequest(
		config.LdapUsers,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		usrFilter(user, host.name, noUsrAcl),
		[]string{"trustModel", "accessTo", "sshPublicKey"},
		nil,
	)

	if sr, err := ldconn.Search(usrReq); err != nil {
		logger.Error(err.Error())
		os.Exit(19)
	} else if len(sr.Entries) > 1 {
		logger.Warn("More than 1 user with uid %s, aborting", user)
	} else if len(sr.Entries) > 0 {
		if noUsrAcl || checkAccess(user, host, sr.Entries) {
			return sr.Entries[0].GetAttributeValues("sshPublicKey")
		}
	}
	return nil
}

func connLdap() (ldap.Client, int) {
	var code = -1

	for _, server := range config.LdapServers {
		if conn, err := ldap.Dial("tcp", server); err != nil {
			logger.Error(err.Error())
			code = 15
			continue
		} else {
			if config.LdapStartTLS {
				if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: config.LdapIgnoreCert, ServerName: strings.Split(server, ":")[0]}); err != nil {
					logger.Error(err.Error())
					conn.Close()
					code = 16
					continue
				}
			}

			if err := conn.Bind(config.LdapBind, config.LdapPass); err != nil {
				logger.Error(err.Error())
				conn.Close()
				code = 17
				continue
			}
			return conn, 0
		}
	}
	return nil, code
}

func usrFilter(user, host string, noUsrAcl bool) string {
	var filter string
	if !noUsrAcl {
		filter = aclFilter(host)
	}
	return u.StrCat("(&(objectclass=posixAccount)(uid=", user, ")", filter, ")")
}

func grpFilter(user, host string) string {
	return u.StrCat("(&(objectclass=posixGroup)(memberUid=", user, ")", aclFilter(host), ")")
}

func aclFilter(host string) string {
	return u.StrCat("(|(trustmodel=fullaccess)(accessTo=+*)(accessTo=", host, "))")
}
