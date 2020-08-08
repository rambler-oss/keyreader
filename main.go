package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"log/syslog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	u "github.com/iavael/goutil"
	"golang.org/x/crypto/ssh"
	"gopkg.in/ldap.v2"
)

var (
	confpath string
	debugOn  bool

	config Config
	logger *u.Logger

	ldconn ldap.Client
)

func main() {
	var (
		host Host
		user string
	)

	flag.Usage = func() {
		os.Stderr.WriteString("Usage of ")
		os.Stderr.WriteString(os.Args[0])
		os.Stderr.WriteString(":\n")
		flag.PrintDefaults()
	}

	flag.StringVar(&confpath, "config", configPath, "Path to config file")
	flag.BoolVar(&debugOn, "debug", false, "Debug ON")
	flag.Parse()

	if slog, err := syslog.New(syslog.LOG_DAEMON, "keyreader"); err != nil {
		log.Printf("Failed to create new syslog: %s\n", err)
		logger = u.NewLogger(u.NONE, nil)
	} else {
		defer slog.Close()
		logger = u.NewLogger(u.DEBUG, slog)
	}
	debugLog("Welcome to debug mode!")
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
	debugLog("Hostnames:")
	for _, hostname := range host.names {
		debugLog("Hostname:\t%s", hostname)
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

	handleSigPipe()

	for i, key := range checkUser(user, &host) {
		if !strings.HasSuffix(key, "\n") {
			key = strCat(key, "\n")
		}
		if err := printKey(i, key); err != nil {
			logger.Warn(err.Error())
		}
	}
}

func handleSigPipe() {
	sigpipe := make(chan os.Signal, 1)
	go func(sigchan <-chan os.Signal) {
		for range sigchan {
			os.Exit(0)
		}
	}(sigpipe)
	signal.Notify(sigpipe, syscall.SIGPIPE)
}

func printKey(i int, key string) error {
	if config.FilterByFrom() {
		if _, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(key)); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New(strCat("SSHKey element #", strconv.Itoa(i), " has more than 1 key"))
		} else {
			fromFound := false
			for _, opt := range opts {
				if strings.HasPrefix(opt, "from=") {
					fromFound = true
					break
				}
			}
			if !fromFound {
				return errors.New(strCat("No host is bound to ssh key ", key))
			}
		}
	}
	_, err := os.Stdout.WriteString(key)
	debugLog("Key printed!")
	return err
}

func checkGroup(user string, host *Host) bool {
	debugLog("Check groups permissions")

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
			if checkAccess(user, host, sr.Entries) {
				// Just get keys, don't check user's accessTo
				logger.Info("Access granted to user %s by group permissions", user)
				return true
			}
		} else {
			debugLog("LDAP check user group:\tno entries")
		}
	}
	return false
}

func checkUser(user string, host *Host) []string {
	// Don't check user's acl if their group has permission
	debugLog("Check user permissions %s", user)

	noUsrACL := checkGroup(user, host)

	debugLog("Will not check user's acl:\t%t", noUsrACL)
	usrReq := ldap.NewSearchRequest(
		config.GetLdapUsers(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		usrFilter(user, host.names, noUsrACL),
		[]string{"trustModel", "accessTo", "sshPublicKey"},
		nil,
	)

	if sr, err := ldconn.Search(usrReq); err != nil {
		logger.Error(err.Error())
		os.Exit(19)
	} else if len(sr.Entries) > 1 {
		logger.Warn("More than 1 user with uid %s, aborting", user)
	} else if len(sr.Entries) > 0 {
		if noUsrACL || checkAccess(user, host, sr.Entries) {
			return sr.Entries[0].GetAttributeValues("sshPublicKey")
		} else {
			debugLog("User %s has not access to %s", user, host)
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
	return strCat("(&(objectclass=posixAccount)(uid=", user, ")", filter, ")")
}

func grpFilter(user string, hosts []string) string {
	return strCat("(&(objectclass=posixGroup)(memberUid=", user, ")", aclFilter(hosts), ")")
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
	return strCat(filter...)
}

func strCat(list ...string) string {
	var res strings.Builder
	for _, s := range list {
		res.WriteString(s)
	}
	return res.String()
}
