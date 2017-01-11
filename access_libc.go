// +build libc,!ldap cgo,!freebsd,!ldap

package main

/*
#cgo LDFLAGS: -lc
#include <stdlib.h>
#include <netdb.h>

static int innetgroup(const char* netgroup, const char* host) {
	return innetgr(netgroup, host, 0, 0);
}
*/
import "C"

import (
	"unsafe"
)

func (h Host) inNetGroups(netgroups []string) bool {
	for _, netgroup := range netgroups {
		for _, host := range h.names {
			if nssInNetGr(host, netgroup) {
				logger.Info("Found host %s in netgroup %s", host, netgroup)
				return true
			}
		}
	}
	return false
}

func nssInNetGr(host, netgroup string) bool {
	logger.Debug("Checking %s for membership in %s", host, netgroup)
	cnetgr := C.CString(netgroup)
	defer C.free(unsafe.Pointer(cnetgr))
	chost := C.CString(host)
	defer C.free(unsafe.Pointer(chost))
	if C.innetgroup(cnetgr, chost) > 0 {
		return true
	}
	return false
}
