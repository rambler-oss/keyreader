// +build cgo

package main

/*
#cgo LDFLAGS: -lc
#include <malloc.h>
#include <netdb.h>

static int innetgroup(const char* netgroup, const char* host) {
	return innetgr(netgroup, host, NULL, NULL);
}
*/
import "C"

import (
	"unsafe"

	"gopkg.in/ldap.v2"
)

func inNetGroup(netgroup, host string) bool {
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

func inNetGroups(_ *ldap.Conn, netgroups []string) bool {
	for _, netgroup := range netgroups {
		if inNetGroup(netgroup, hostname) {
			logger.Info("Found host %s in netgroup %s", hostname, netgroup)
			return true
		}
	}
	return false
}
