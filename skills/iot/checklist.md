# IoT / Embedded — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Authorized firmware acquired (download / OTA capture / flash dump) + format identified
- [ ] Approval obtained (RoE — authorized device/image) + in-scope models/images confirmed

## Test (scope-gated, benign)
- [ ] Filesystem extracted + entropy/packing analyzed
- [ ] Hardcoded/default creds + keys + certs hunted — secrets REDACTED in artifacts
- [ ] Update mechanism reviewed (signing / transport / rollback)
- [ ] Hardware interfaces (UART/JTAG/SWD console, SPI-flash dump) checked where device provided
- [ ] Key embedded binaries analyzed (auth / update / network services)
- [ ] Exposed network services + default configs mapped
- [ ] One issue confirmed benignly (recover a default/hardcoded secret / reach a console) — no bricking/flashing
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid, secrets redacted)
- [ ] poc/ per finding
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
