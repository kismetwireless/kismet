#!/usr/bin/env python

import sys, KismetRest

if len(sys.argv) < 2:
    print "Expected server URI"
    sys.exit(1)

kr = KismetRest.KismetConnector(sys.argv[1])

kr.set_login("kismet", "kismet")

if not kr.check_session():
    kr.login()

print "login"
kr.login();
print "posting"


kr.post_url("datasource/add_source.cmd", { "definition": sys.argv[2] })

