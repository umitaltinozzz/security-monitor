---
title: Data sources
description: Planned advisory providers, attribution, freshness, and result semantics.
---

# Data sources

The current implementation does not fetch or evaluate advisory data. The sources below are part of the planned product and are not yet integrated.

| Source | Planned role | Important limitation |
| --- | --- | --- |
| [cve.now](https://cve.now/) | Primary feed for newly published vulnerabilities and merged references | Its package-version data can lag; integrations must show the last successful refresh and stale state. Do not upload a lockfile or package list by default. |
| [OSV](https://osv.dev/) | Offline vulnerability database for package/version matching | Downloaded database freshness must be visible; online package-list scanning is disabled by default. |
| GitHub Advisory Database | Advisory enrichment and source cross-checking | Preserve the advisory source and affected-range provenance. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerability evidence | A catalog absence is not proof that a vulnerability is not exploited. |
| [FIRST EPSS](https://www.first.org/epss/) | Exploitation probability context | Display its date and source; it is a probability, not confirmation of exploitation. |
| [NVD](https://nvd.nist.gov/) | CVE, product, and vulnerability enrichment | Data coverage and enrichment can be incomplete or delayed. Include the notice below when using NVD API data. |
| ENISA EUVD and Exploit-DB | Additional reference and exploitation context | Keep source and retrieval time visible; do not infer safety from missing entries. |

## Attribution and terms

If the application displays cve.now's summaries, attribute [cve.now](https://cve.now/) and link to [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). cve.now combines data from several providers; this summary license does not replace the terms of each underlying source.

When using NVD API data, display this notice:

> This product uses data from the NVD API but is not endorsed or certified by the NVD.

Where CVE records are redistributed, follow the [CVE Program Terms of Use](https://www.cve.org/ResourcesSupport/TermsOfUse). Each provider's data should retain its own attribution and terms.

## Result semantics

Local OSV data is the planned authority for affected package-version matching. cve.now is the planned fast alert feed, not the sole source of affected version ranges. Conflicting ranges or incomplete product/version evidence must remain `needs_review`; a missing record, provider outage, stale cache, or unavailable scanner must be shown as unverified.
