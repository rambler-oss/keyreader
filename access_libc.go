// +build libc,!ldap cgo,!freebsd,!ldap

package main

/*
#cgo LDFLAGS: -lc
#include <stdlib.h>
#include <netdb.h>
*/
import "C"

import (
	"unsafe"
)

func (h Host) inNetGroups(netgroups []string) bool {
	debugLog("Search host in netgroups: \t%s", netgroups)
	for _, netgroup := range netgroups {
		for _, host := range h.names {
			if nssInNetGr(netgroup, &host, nil, nil) {
				logger.Info("Found host %s in netgroup %s", host, netgroup)
				return true
			}
		}
	}
	return false
}

func nssInNetGr(netgroup string, host, user, domain *string) bool {
	var (
		chost   *C.char
		cuser   *C.char
		cdomain *C.char
	)
	logger.Debug("Checking %s for membership in %s", *host, netgroup)
	cnetgr := C.CString(netgroup)
	defer C.free(unsafe.Pointer(cnetgr))
	if host != nil {
		chost = C.CString(*host)
		defer C.free(unsafe.Pointer(chost))
	} else {
		chost = nil
	}
	if user != nil {
		cuser = C.CString(*user)
		defer C.free(unsafe.Pointer(cuser))
	} else {
		cuser = nil
	}
	if domain != nil {
		cdomain = C.CString(*domain)
		defer C.free(unsafe.Pointer(cdomain))
	} else {
		cdomain = nil
	}
	if C.innetgr(cnetgr, chost, cuser, cdomain) > 0 {
		return true
	}
	return false
}
