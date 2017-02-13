package main

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	u "github.com/iavael/goutil"
)

var oldGroupRegex = regexp.MustCompile(`^([^[:digit:]]+)(?:[[:digit:]]+)(.*)$`)

var oldGroupsFlag bool

func getOldDomains() []string {
	olddomains := []string{
		"rambler.ru",
		"rambler.tech",
		"afisha.ru",
		"autorambler.ru",
	}

	if _, err := os.Stat(oldgrpPath); os.IsNotExist(err) {
		if oldGroupsFlag {
			return olddomains
		}
		return nil
	}

	if file, err := os.Open(oldgrpPath); err != nil {
		logger.Error(err.Error())
		os.Exit(20)
	} else {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if str := scanner.Text(); len(str) > 0 {
				olddomains = append(olddomains, str)
			}
		}
		if err := scanner.Err(); err != nil {
			logger.Error(err.Error())
			os.Exit(21)
		}
	}
	return olddomains
}

func oldGroups() []string {
	var result = []string{}
	if name, err := os.Hostname(); err != nil {
		logger.Error(err.Error())
		os.Exit(12)
	} else {
		var prefix string
		for _, dom := range getOldDomains() {
			logger.Debug("Checking suffix %s for %s", dom, name)
			if strings.HasSuffix(name, dom) {
				prefix = name[:len(name)-len(dom)-1]
				break
			}
		}
		if len(prefix) == 0 {
			return result
		}
		if matches := oldGroupRegex.FindStringSubmatch(prefix); len(matches) == 3 {
			group := u.StrCat(matches[1], matches[2])
			logger.Warn("Using deprecated group %s", group)
			result = append(result, group)
		}
	}
	return result
}
