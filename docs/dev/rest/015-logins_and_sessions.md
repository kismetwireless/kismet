---
title: "Logins and sessions"
permalink: /docs/devel/webui_rest/logins/
---

Kismet uses basic auth to submit login information, and session cookies to retain login state.  

Typically, GET endpoints which do not reveal sensitive data do not require a login, while the majority of POST endpoints, as well as GET endpoints which return packet streams or other configuration information, *will* require login information.

A session will automatically be created during authentication to any endpoint which requires login information, and returned in the `KISMET` session cookie.

Logins may be manually validated against the `/session/check_session` endpoint if validating user-supplied credentials.

### Checking sessions
A script can check for a valid session and prompt the user to take action if a session is no longer valid.

Login data may be provided; if the session is not valid, and valid login data is provided via basic auth, a session will be created.

* URL \\
        /session/check_session

* Methods \\
        `GET`

* Result \\
        `HTTP 200` is returned if the session is valid. \\
        HTTP error returned if session is *not* valid and supplied login data, if any, is not valid.

### Checking logins
A script may need to check for a valid login and prompt the user to take action if the login credentials are not valid.

Session cookies will be ignored while checking logins.

* URL \\
        /session/check_login

* Methods \\
        `GET`

* Result \\
        `HTTP 200` is returned if the login is valid. \\
        HTTP error returned if the login is not valid.

