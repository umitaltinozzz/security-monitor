---
title: Data sources
description: Advisory providers, attribution, freshness, and result semantics.
---

# Data sources

Security Monitor downloads public advisory data and keeps provider caches on the device. It does not upload lockfiles, source code, package names, or inventory to these providers. Filtered cve.now feeds are not used because their query parameters would disclose inventory-derived ecosystem or technology names.

| Source | Current use | Freshness and attribution |
| --- | --- | --- |
| [cve.now](https://cve.now/) | Primary incremental source for new and changed advisories. Poll `GET /api/v1/status`, then read cursor-paginated entries and their public details. | Default poll interval is 10 minutes (configurable from 5 minutes to 24 hours). The API reports both upstream polling status and historical package-data cutoffs; missing, unhealthy, cached, future-dated, or over-24-hour source status is stale. Summaries are CC BY 4.0: attribute cve.now and link to the entry. Package-version data can lag by days, so OSV remains the package matching source. |
| [OSV](https://osv.dev/) | Per-ecosystem offline vulnerability database for package and version matching. Only ecosystems present in the local inventory are refreshed. | Default refresh is hourly. Keep the database local and mark it stale when unavailable or older than the refresh interval. OSV aggregates data under different upstream licenses; preserve `database_specific.source` attribution when available and do not infer one blanket license for all OSV records. |
| [GitHub Advisory Database](https://github.com/advisories) | Direct cross-check by public GHSA ID for new cve.now records. | At most 10 lookups run per refresh; any remaining or failed checks leave the provider stale. Attribute GHSA records under CC BY 4.0 and retain their affected-range source. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Daily full-catalog enrichment for known exploitation. | Use the local cache when offline and mark it stale. A catalog absence is not proof that a vulnerability is not exploited. |
| [FIRST EPSS](https://www.first.org/epss/) | Daily CSV enrichment for exploit probability. | Keep the publication date and FIRST attribution with each score. EPSS is a probability estimate, not confirmation of exploitation. |
| NVD, ENISA EUVD, Exploit-DB, and other feeds | References and upstream source records supplied by cve.now. | Preserve each source's name, URL, and license terms from the returned advisory. This implementation does not make separate direct API calls to these providers. |

## Attribution and terms

If the application displays cve.now's summaries, attribute [cve.now](https://cve.now/) and link to [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The cve.now response identifies the summary model; preserve that label with the summary. cve.now combines data from several providers, so its summary license does not replace the terms or attribution of each underlying source.

GitHub Advisory Database data is CC BY 4.0. FIRST requests attribution for EPSS data. OSV is an aggregator whose source databases use different licenses; preserve per-record source attribution when supplied and leave the license unspecified when it cannot be verified. Do not assign a license to CISA data without a source-specific grant.

When using NVD API data, display this notice:

> This product uses data from the NVD API but is not endorsed or certified by the NVD.

Where CVE records are redistributed, follow the [CVE Program Terms of Use](https://www.cve.org/ResourcesSupport/TermsOfUse). Each provider's data should retain its own attribution and terms.

## Result semantics

Local OSV data is the authority for affected package-version matching. cve.now is the fast alert feed, not the sole source of affected version ranges. Product-only records match an inventory component only by normalized exact product name and remain `needs_review` while package or version data is pending. Unsupported range semantics, conflicting source ranges, and incomplete product/version evidence remain `needs_review`. A missing record, provider outage, stale cache, or unavailable provider must be shown as unverified; an empty result is not a clean bill of health.
