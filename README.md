[![Build Status](https://travis-ci.org/rambler-oss/keyreader.svg?branch=master)](https://travis-ci.org/rambler-oss/keyreader)
[![Code Climate](https://codeclimate.com/github/rambler-oss/keyreader/badges/gpa.svg)](https://codeclimate.com/github/rambler-oss/keyreader)

SSH keyreader with authorization via LDAP
=========================================

Features
--------

* Reads standard PosixAccount and PosixGroup object classes
* Uses GoSa authorization scheme (trustModel and accessTo attributes)
* Can read authorization not only from user entries but from groups too
* Support NIS netgroups in accessTo attributes with sudo-compatible syntax, 
netgroups are distinguished by prepending 'plus' sign 
(accessTo: hostname, accessTo: +netgroup)
* Netgroups are received via libnss (you can back it to ldap by libnss-ldap or sssd)
* Keyreader can ignore keys without "from" option

How authorization works
-----------------------

1. keyreader is launched by sshd with user login in argv[1]
1. keyreader looks for PosixGroup objects where user is member
1. keyreader validates if found posix groups have this host in accessTo
1. keyreader gets all netgroups which found posix groups have in accessTo
1. keyreader checks if any netgroup has this host in members
1. if keyreader founds granted access, it looks for user with uid same as login and print their ssh pubkeys to stdout, otherwise it does 3-5 steps, but for PosixAccount instead of PosixGroup
1. sshd reads ssh keys (if there're any) and uses them to authenticate user
