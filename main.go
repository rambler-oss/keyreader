package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"log/syslog"
	"os"
	"strconv"
	"strings"

	u "github.com/iavael/goutil"
	"golang.org/x/crypto/ssh"
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
}

func main() {
	var (
		host Host
		user string
	)

	if slog, err := syslog.New(syslog.LOG_DAEMON, "keyreader"); err != nil {
		log.Fatalf("Failed to create new syslog: %s", err)
	} else {
		defer slog.Close()
		logger = u.NewLogger(u.INFO, slog)
	}

	if cfg, err := u.NewMultiConfig(confpath, &ConfigVer{}, selectConfig); err != nil {
		logger.Error("Config file error: %s", err)
		os.Exit(10)
	} else {
		config = cfg.(Config)
	}

	if names := config.GetHostnames(); len(names) != 0 {
		host.names = names
	}
	if name, err := os.Hostname(); err != nil {
		logger.Error(err.Error())
		os.Exit(12)
	} else if !u.MemberOfSlice(name, host.names) {
		host.names = append(host.names, name)
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

	for i, key := range checkUser(user, &host) {
		if err := printKey(i, key); err != nil {
			logger.Warn(err.Error())
		}
	}
}

func printKey(i int, key string) error {
	if config.FilterByFrom() {
		if _, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(key)); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New(u.StrCat("SSHKey element #", strconv.Itoa(i), " has more than 1 key"))
		} else {
			fromFound := false
			for _, opt := range opts {
				if strings.HasPrefix(opt, "from=") {
					fromFound = true
					break
				}
			}
			if !fromFound {
				return errors.New(u.StrCat("No host is bound to ssh key ", key))
			}
		}
	}
	os.Stdout.WriteString(key)
	os.Stdout.WriteString("\n")
	return nil
}

func checkGroup(user string, host *Host) bool {
	grpReq := ldap.NewSearchRequest(
		config.GetLdapGroups(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		grpFilter(user, host.names),
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
		config.GetLdapUsers(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		usrFilter(user, host.names, noUsrAcl),
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
	logger.Warn("Failed to authorize user %s", user)
	return nil
}

func connLdap() (ldap.Client, int) {
	var code = -1

	for _, server := range config.GetLdapServers() {
		if conn, err := ldap.Dial("tcp", server); err != nil {
			logger.Error(err.Error())
			code = 15
			continue
		} else {
			if config.GetLdapStartTLS() {
				if err := conn.StartTLS(&tls.Config{
					InsecureSkipVerify: config.GetLdapIgnoreCert(),
					ServerName:         strings.Split(server, ":")[0],
				}); err != nil {
					logger.Error(err.Error())
					conn.Close()
					code = 16
					continue
				}
			}

			if err := conn.Bind(
				config.GetLdapBind(),
				config.GetLdapPass(),
			); err != nil {
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

func usrFilter(user string, hosts []string, noUsrAcl bool) string {
	var filter string
	if !noUsrAcl {
		filter = aclFilter(hosts)
	}
	return u.StrCat("(&(objectclass=posixAccount)(uid=", user, ")", filter, ")")
}

func grpFilter(user string, hosts []string) string {
	return u.StrCat("(&(objectclass=posixGroup)(memberUid=", user, ")", aclFilter(hosts), ")")
}

func aclFilter(hosts []string) string {
	filter := []string{
		"(|(trustmodel=fullaccess)(accessTo=+*)",
	}
	for _, host := range hosts {
		filter = append(filter, "(accessTo=")
		filter = append(filter, host)
		filter = append(filter, ")")
	}
	filter = append(filter, ")")
	return u.StrCatS(filter)
}
