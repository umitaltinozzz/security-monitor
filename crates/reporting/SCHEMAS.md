# Vendored report schemas

These schemas are committed so validation tests run offline and cannot change underneath a build.

| File | Standard | Source | License |
| --- | --- | --- | --- |
| schemas/sarif-2.1.0.schema.json | OASIS SARIF 2.1.0 Committee Specification 01 | https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json | OASIS Open Document License |
| schemas/cyclonedx-bom-1.6.schema.json | CycloneDX 1.6 | https://cyclonedx.org/schema/bom-1.6.schema.json | Apache-2.0 |
| schemas/spdx.schema.json | CycloneDX vendored SPDX definition | https://cyclonedx.org/schema/spdx.schema.json | Apache-2.0 |
| schemas/jsf-0.82.schema.json | CycloneDX vendored JSON Signature Format 0.82 definition | https://cyclonedx.org/schema/jsf-0.82.schema.json | Apache-2.0 |
| schemas/openvex-0.2.0.schema.json | OpenVEX 0.2.0 | https://raw.githubusercontent.com/openvex/spec/main/openvex_json_schema.json | Apache-2.0 |

The OASIS SARIF schema contains an invalid locale regular expression in two locations (^[a-zA-Z]{2}|^[a-zA-Z]{2}-[a-zA-Z]{2}]?$). The validator applies the equivalent valid expression (^[a-zA-Z]{2}(-[a-zA-Z]{2})?$) in memory before compiling the vendored schema. The committed upstream file is not modified.

Do not fetch schema files during builds or tests. A schema update must pin a released standard version, update this table, and keep fixture validation offline.
