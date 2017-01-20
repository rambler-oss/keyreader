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
	for _, netgroup := range netgroups {
		for _, host := range h.names {
			if nssInNetGr(&netgroup, &host, nil, nil) {
				logger.Info("Found host %s in netgroup %s", host, netgroup)
				return true
			}
		}
	}
	return false
}

func nssInNetGr(netgroup, host, user, domain *string) bool {
	logger.Debug("Checking %s for membership in %s", host, netgroup)
	cnetgr := C.CString(*netgroup)
	defer C.free(unsafe.Pointer(cnetgr))
	chost := C.CString(*host)
	defer C.free(unsafe.Pointer(chost))
	if C.innetgr(cnetgr, chost, user, domain) > 0 {
		return true
	}
	return false
}
