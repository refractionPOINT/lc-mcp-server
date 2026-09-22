# CS-02 IaC provenance reads

Finding list, facets, cause rollups and CSV export accept `iac_attribution`, an
array of one to four exact verdicts: `attributed`, `ambiguous`, `none`, `unknown`.
They and inventory list/facets/export accept the optional boolean
`has_iac_origin`. Explicit false is preserved. Missing, malformed and oversized
selectors are distinct: malformed supplied selectors fail locally before HTTP;
omitting a selector leaves that dimension unconstrained.

False means no recorded resource-origin evidence, not proof of no IaC. Missing,
partial or stale evidence never establishes safety. Facet dimensions exclude
their own selector. All requests use the existing authenticated organization
context; selectors cannot choose another tenant. Resource point reads pass
through the bounded optional `iac_origin` and `iac_origin_partial` fields,
including origins for clean resources. Immutable source links are optional;
missing revision metadata stays unknown and must not become a HEAD link.
The tools never fetch source URLs or source code.

Compatibility: use after graph PR228 and gateway PR962 are deployed with
provenance queries enabled. The disabled server rejects explicit new selectors.
No tool enables features, changes IAM, or writes resources. Roll back by disabling
provenance server-side and omitting selectors/reverting this client; retain schema.

Package: https://github.com/maximelb/claude-config/issues/137
Epic: https://github.com/maximelb/claude-config/issues/134
Graph: https://github.com/refractionPOINT/legion_graph/pull/228
Gateway owner draft: https://github.com/refractionPOINT/lc_api-go/pull/962

Rolling-version proof: JSON reads with new selectors require an exact
`applied_iac_filters` response receipt. CSV exports require a bounded first line
`# lc_iac_filters_v1=<base64url JSON receipt>`; the tool validates and removes it
before returning CSV. Missing/mismatched receipts are errors, including successful
responses from older gateways/readers. Selector-free legacy responses are unchanged.
