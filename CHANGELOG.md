# Changelog

All notable changes to acme-nv are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 rule that a breaking change bumps the MINOR number.

## 0.1.0 — 2026-11-01

Every function has a body. The suites run against RFC 8555's own
documents, RFC 7638 section 3.1's published thumbprint, RFC 7515
appendix A.3's key and signature, certification requests made by
Python's `cryptography` package, and a local ACME server that verifies
what the client sends with its own code. Line coverage of `src/` is
100%, with two sites excused by a `cov: skip` marker that gives its
reason.

### Changed

- The dependencies are registry ranges at the newest published
  versions: jwt-nv `^0.1`, p256-nv `^0.1`, asn1-nv `^0.1`, base64-nv
  `^0.1` and calendar-nv `^0.2`. p256-nv 0.1.0 carries ECDSA, so the
  signing function an ACME request needs exists; the package still takes
  it as an argument, for a key that is held outside the process.
- Breaking: `acmejws.thumbprint` takes its buffer as `var out`, because
  it writes the digest into it.
- Breaking: `acmejws.protected_header` no longer decides from the URL
  whether a request wanted a `jwk` or a `kid`, since only the directory
  knows which URL is newAccount. It refuses an empty `kid` and a `jwk`
  that is not canonical, and `acmeclient.post` makes the directory-based
  check: a `kid` on newAccount and a `jwk` anywhere but newAccount and
  revokeCert are refused before anything is sent, as
  `AcmeClientBadSignature(AcmeJwsWrongKeyId(...))`.
- Breaking: `AcmeExchange` has a new field, `links`, holding every
  `Link` header line, because `link_up` alone could not carry the
  alternate chains `alternate_chains` reads.
- Breaking: `AcmeJwsFault` has two new variants, `AcmeJwsBufferTooSmall`
  and `AcmeJwsNotBase64Url`, and `AcmeClientFault` has two,
  `AcmeClientRateLimited(problem, retry_after)`, which carries the wait
  the server asked for, and `AcmeClientInsecureUrl(url)`.
- `acmerenew` computes in whole seconds and returns the window as
  `opens` no earlier than the certificate's start and `closes` no later
  than its end.

### Added

- `acmeclient` refuses any URL that is not https, except a loopback
  address, before a request is made. The directory's URLs are held to
  the same rule.
- `acmeclient.finalize` falls back to the finalise URL as the order's URL
  when the reply has no `Location` header.
- `tests/double/acme_double.py`, a local ACME server for the client
  suite, and `tests/coverage.sh`, which merges the line coverage of the
  suites over `src/`.

This release requires novo 0.23.0 or later.

## 0.0.2 — 2026-09-12

### Changed — The README is rewritten in plain technical-writer prose; no signature changed.

## 0.0.1 — 2026-09-12

The **interface**: every signature and every effect row, and no bodies.
`stability = "draft"`, and the release is recorded `implemented = false`.

### Added

- `acmemsg` — the directory, the account, the order, the
  authorization, the challenge and RFC 7807's problem document, `[]`
  throughout: the three terminal-status predicates a polling loop
  needs, `problem_is_bad_nonce` for the error that is a retry, and
  `identifier_for` for the lookup that cannot be done by string because
  a wildcard's authorization carries the base name.
- `acmejws` — the request signature, `[]` throughout: `AcmeNonce` as a
  value so the single-use rule is the type, `AcmeJwsKeyId` with two
  cases so a header cannot carry both `jwk` and `kid`, RFC 7638's
  canonical JWK and thumbprint, the key authorization, and
  `post_as_get_payload` as the empty string it is.
- `acmechal` — the four challenge values a caller publishes itself,
  `[]` throughout: `token_is_wellformed` checked before a token becomes
  a filesystem path, the HTTP-01 body with no trailing newline, and the
  DNS-01 record name a wildcard shares with its base name.
- `acmecsr` — PKCS#10 over asn1-nv, `[]` throughout: the names in the
  SAN and an empty subject, and `names_match` public so a caller checks
  before a finalise that cannot be retried.
- `acmerenew` — when to renew, `[]` throughout with "now" as an
  argument: a fraction of the lifetime rather than a fixed offset, a
  window rather than an instant, and negative days left rather than
  zero.
- `acmeclient` — the one module that performs anything,
  `[io, net, time, async]`: POST-as-GET for every read, one automatic
  `badNonce` retry, and one request per poll with the loop left to the
  caller.
- API tests in `tests/acmeflow_tests.nv` and
  `tests/acmeclient_tests.nv`, red until the bodies land.

### Named as missing

ECDSA signing over P-256, which p256-nv does not carry, and a raw
signer in jwt-nv for a JWS that is not a JWT — both argued in the
README.  Until they land, the signing function is an argument.
