# acme-nv

**Status: NOT IMPLEMENTED — interface only.**

Every public function below is published with its signature and its
effect row, and every body is `todo()`.  Installing this package works;
calling it panics with `not implemented`.

## What this is

An ACME client (RFC 8555) — the protocol Let's Encrypt and its
successors speak.  Account creation, orders, the HTTP-01 and DNS-01
challenges, certificate request generation, finalisation, certificate
download, revocation, and the arithmetic that says when to renew.

It gets a certificate issued.  It does not serve the challenge, update
your DNS, write anything to disk, or run a scheduler — each of those is
a decision about a machine this package knows nothing about, and the
section below says so for each one.

## Adding it, and checking it

```bash
novo pkg add acme-nv         # into your novo.toml
novo pkg build               # type- and effect-check the package
novo test --isolate tests/acmeflow_tests.nv
```

`novo test` is red today and that is the point of the release: every
assertion fails with `not implemented: acme-nv.<module>.<fn>`.  They
turn green one at a time as bodies land.

## The one example that will work

```novo
use acmechal
use acmeclient
use acmejws
use acmemsg

// Order a certificate for one name, proving control with HTTP-01.
//
// `sign` is a named function the caller supplies — see "What is
// missing": there is no ECDSA signer on this grid yet.  `publish` is
// the caller's too: writing the challenge file is a decision about a
// web server this package has never heard of.
fn order(host: Str, jwk: Str, sign: fn(Bytes) -> ?Bytes,
         publish: fn(Str, Str) -> Bool) -> Result<Str, AcmeClientFault> [io, net, time, async]
    let s = acmeclient.session(acmeclient.letsencrypt_staging_directory_url(),
                               acmeclient.signer(Es256, jwk, sign))!

    let n0 = acmeclient.fresh_nonce(s)!
    let registered = acmeclient.new_account(s, n0, ["mailto:ops@example.com"], true)!
    let ordered = acmeclient.new_order(registered.0, registered.2,
                                       [acmemsg.dns_identifier(host)])!

    // One authorization, one challenge, published by the caller.
    let got = acmeclient.authorization(registered.0, ordered.1, ordered.0.authorizations[0])!
    match acmechal.preferred_challenge(got.0, AcmeHttp01)
        None    => Err(AcmeClientNoAccount)
        Some(c) =>
            let path = acmechal.http01_path(c.token)!
            let body = acmechal.http01_body(c.token, jwk)!
            let _ = publish(path, body)
            let told = acmeclient.challenge_ready(registered.0, got.1, c.url)!
            Ok(told.0.url)
```

## The layer, and why

`host`, and five of the six modules declare nothing.

| module | row | why |
| --- | --- | --- |
| `acmemsg` | `[]` throughout | the objects an ACME server serves, as values |
| `acmejws` | `[]` throughout | the protected header, the thumbprint, the key authorization |
| `acmechal` | `[]` throughout | the four challenge values a caller publishes itself |
| `acmecsr` | `[]` throughout | PKCS#10 over asn1-nv |
| `acmerenew` | `[]` throughout | when to renew, with "now" as an argument |
| every request in `acmeclient` | `[io, net, time, async]` | `std.http`'s `HttpClient.send` row |
| `acmeclient.now_civil` | `[time]` | the one clock read the package makes for its own sake |

`layer = "host"` and **not** `layer = "core"` with `host_modules`, for
the reason smtp-nv gave: the package's subject is getting a certificate
issued, and the message shapes are here because a client needs them
rather than the other way round.

## The load-bearing interface

**`AcmeNonce`, and the fact that it is a value rather than a field.**

Every ACME request after the directory fetch is a signed POST carrying
a server-issued nonce in its protected header.  The server checks it,
**discards it**, and returns a fresh one in the reply's `Replay-Nonce`
header.  One nonce, one request, always.

A client that kept the current nonce in a mutable field and sent two
requests from it gets `badNonce` on the second — and only under load,
because a server that is not busy is more forgiving about
near-simultaneous requests.  That is the worst way for a bug to
present: it works on a developer's machine, it works in staging, and it
fails in production on the day a certificate has to be renewed.

So the nonce is a value that is threaded through:

```novo
let ordered = acmeclient.new_order(session, nonce, identifiers)!
// ordered.1 is the NEXT nonce; the one above it is spent.
```

`acmejws.protected_header` takes an `AcmeNonce` and every `acmeclient`
call answers the next one alongside its result.  A caller that wanted
to reuse one has to write code that visibly passes the same binding
twice, which is a thing a reader notices and a mutable field is not.

The second decision follows from the first: **`badNonce` is retried
here, once, automatically.**  RFC 8555 § 6.5 says a client that receives
one MUST retry the same request with the nonce from that very reply, so
it is not an error a caller should ever see.  `acmeclient.post` does
that retry; a *second* `badNonce` for the same request is surfaced,
because twice in a row is a clock skew or a client that is not
following the protocol rather than a busy server.

And the third: **there is no `get` in this package.**  RFC 8555 § 6.3
replaced GET with POST-as-GET — a signed POST whose payload is zero
bytes — so `acmeclient.post_as_get` is how every object is read.  The
empty payload is not `{}`: on a challenge URL `{}` means "start
validating", which is why `acmejws.post_as_get_payload` and
`acmemsg.write_challenge_ready` are two named functions and neither has
a default.

## The four strings that fail silently

Each of these is a value this package builds, and each of them fails
against a real server in a way that says nothing about what was wrong.
So each is a named function with an assertion behind it.

**The JWK thumbprint** (RFC 7638) is a SHA-256 over a canonical JSON
string: only the members the key type requires, member names in
lexicographic order, no whitespace.  For a P-256 key that is exactly
`{"crv":"P-256","kty":"EC","x":"…","y":"…"}`.  One extra member, one
different order, one space, and the thumbprint changes — so the key
authorization changes, so every challenge fails with a message about
the response not matching.  `acmejws.jwk_of_ec` produces the canonical
form and `acmejws.thumbprint` is the only thing that hashes it, so the
protected header's copy of the key and the thumbprint's copy cannot
differ.

**The HTTP-01 body** is the key authorization exactly, with no trailing
newline.  A shell redirect adds one.  RFC 8555 § 8.3 says a server
SHOULD ignore trailing whitespace, and SHOULD is why this is still the
commonest way an HTTP-01 challenge fails.

**The DNS-01 record name for a wildcard is the base name's.**  The
record for `*.example.com` is `_acme-challenge.example.com` — the same
name as for `example.com` itself.  So an order for both needs **two TXT
values at one name**, and a DNS provider API call that *replaces* a
record set rather than adding to it invalidates the first challenge
when it publishes the second.  `acmechal.dns01_records_share_a_name` is
the predicate that says so out loud, and `dns01_names_for` answers the
deduplicated list.

**The signature is encoded two different ways in the same flow.**  An
ACME request's JWS signature is the fixed-width `r || s` — 64 bytes for
ES256.  A certification request's signature is the DER
`SEQUENCE { r, s }`.  Same key, same algorithm, two encodings, one
issuance.  asn1-nv's `ecdsa_signature_rs` and `ecdsa_signature_der`
convert between them, and a client that used one form for both has one
of the two refused with a message about an invalid signature.

## What is missing, by name

This package cannot complete an issuance today, and the reason is one
primitive and one shape.

- **ECDSA signing over P-256.**  `p256-nv` 0.0.2 carries ECDH and
  nothing else — `ecdh`, `key_pair_from_random`, `validate`, and no
  `sign` anywhere.  Every ACME request is signed and so is every
  certification request, so a client without it signs nothing.  The row
  is **p256-nv growing `ecdsa_sign`**, or `ecdsa-nv` beside it,
  crypto/core.  tls-nv names the verification half of the same row from
  the other direction.
- **A raw signer in jwt-nv.**  `jwt-nv` 0.0.3 publishes `JwtAlg`,
  `JwtSigningKey` and `ec_signing_key(p256.SecretKey)` — the key
  vocabulary — and `jwttoken.encode(header, claims, key)`, which signs
  a JWT's compact serialisation over `JwtClaims`.  An ACME request is
  the **flattened JSON** serialisation over a protected header
  containing a nonce and a URL, which is not a claims set, so
  `encode` is the wrong shape and `signing_input` takes the wrong
  arguments.  What would close it is one function —
  `jwtalg.sign_raw(key: JwtSigningKey, input: Bytes) -> Result<Bytes, JwtError>`
  — and it would serve paseto-nv and any other JWS profile too.

Until then `acmejws.signed_request` and `acmeclient.signer` take the
signing function as an argument.  That is not purely a stopgap: a
caller whose account key lives in a hardware token or a cloud key
service supplies a function there and never holds the key, which is
what such a caller wants anyway.

## Where a row wanted to widen

**`[io, net, time, async]` where the plan's row said `[net, time]`.**
Every request in `acmeclient` costs all four, and none of the four is
this package's choice: they are `std.http`'s `HttpClient.send` row.
`[async]` because the transport parks on the socket, `[time]` because
the request deadline is read from a clock, `[io]` because the
connection surface under it declares it.

The alternative was the narrower one-shot verbs — `http.client.get`
returns `?Str` at `[net, async]` — and they cannot be used here at all:
they discard the response headers, and an ACME client that cannot read
`Replay-Nonce` cannot make a second request, cannot read `Location` so
cannot learn its own account URL or its order's URL, and cannot read
`Retry-After` so cannot honour a rate limit.  So the row is the honest
one, and it is recorded here rather than trimmed.

## What this does not do, on purpose

- **It does not serve the challenge.**  An HTTP-01 challenge is a file
  at a path, and where that file goes depends on whether the caller
  runs a web server, a reverse proxy, a static host, or nothing at all
  on port 80.  `acmechal.http01_path` and `.http01_body` are the two
  values; putting them somewhere is the caller's.
- **It does not update DNS.**  A DNS-01 challenge is a TXT record, and
  publishing one is an API call to whichever of forty providers holds
  the zone.  `acmechal.dns01_record_name` and `.dns01_record_value` are
  the two values.
- **It does not poll and it does not sleep.**  `poll_order`,
  `poll_authorization` and `poll_challenge` each perform exactly one
  request; the loop, the backoff and the deadline are the caller's,
  with `acmerenew.poll_backoff_seconds` as the schedule.  A library
  that ran its own loop would own a timeout policy for a process it
  knows nothing about, and would hide the one thing an operator
  watching an issuance wants to see.
- **It does not store anything.**  No account key on disk, no
  certificate written, no state file.  `acmerenew` says *when* to
  renew; where the certificate and the key live is the program's.
- **It does not do TLS-ALPN-01.**  That challenge is answered during a
  TLS handshake with a certificate carrying a specific extension, so it
  needs a TLS server that can be told to present one — which is tls-nv,
  and tls-nv is an interface too.  `AcmeTlsAlpn01` exists as a value so
  a challenge list round-trips, and `acmechal.kind_can_answer` answers
  false for it.
- **It does not do external account binding.**  A commercial CA that
  requires one needs an HMAC over the account key with a key issued out
  of band; `AcmeDirectory.external_account_required` says when a server
  wants it, and the rest is an honest gap.
- **It does not generate keys.**  An account key and a certificate key
  are `p256-nv`'s `key_pair_from_random`, whose randomness is the
  caller's.
- **No device claim.**  The package is `host`.

## What the registry site's own certificate story would use

`registry.novo-lang.org` and the site beside it are one host with a
small, fixed set of names and a deploy script that already runs as
root.  The shape that fits is **DNS-01 for a wildcard, renewed from a
scheduled run**, and the reason is the two constraints the host has:
the registry answers on 443 and would rather not open 80 for the sole
purpose of answering a challenge, and a wildcard is worth having
because a new subdomain should not need a new certificate.

Concretely: one account key held where the deploy secrets already live
(see keyring-nv, which is this lane's answer to where that is), an
order for `novo-lang.org` and `*.novo-lang.org`, `acmechal.dns01_names_for`
answering the one TXT record name both identifiers share,
`acmerenew.default_policy` deciding when — at two thirds of ninety days,
so a failure has thirty days to be noticed in — and
`acmerenew.renewal_window` spreading the attempt so that a second host
added later does not renew in the same minute.

What that story needs before it can be written: the ECDSA signer above,
and a DNS provider call for whoever holds the zone.  Neither is this
package's to supply, and both are named rather than assumed.

## The reference implementation

`instant-acme` (Rust) for the shape — its `Account`/`Order`/
`Authorization` split, and its decision to hand the challenge values
back to the caller rather than serving them, are both ported directly.
`certbot` for the operational surface: the staging directory named
beside the production one, the renewal fraction, and the insistence
that a failed challenge's `detail` is the only useful thing in a
failure.  RFC 8555 is the specification, RFC 7638 the thumbprint, RFC
7515 and RFC 7517 the JWS and the JWK, and RFC 2986 the certification
request.

Three things change in the port.

`instant-acme` keeps the current nonce in the account object and
refreshes it internally; here it is a value the caller threads, for the
reason the load-bearing section gives — the single-use rule is worth
having in the types rather than in a comment.

`instant-acme` signs with `ring` behind a `Signer` trait it owns; here
the signing function is an argument, because there is no signer on this
grid to own.

And certbot's plugin architecture — the thing that makes it able to
publish an HTTP-01 challenge through nginx or a DNS-01 challenge
through fifty providers — is not ported at all.  A plugin interface
here would be a trait with an effect parameter and a package that
depended on nothing, which is a worse deal than four strings and a
caller that knows its own infrastructure.

## Status

| item | implemented |
| --- | --- |
| `acmemsg` — `AcmeDirectory`, `AcmeAccountStatus`, `AcmeAccount`, `AcmeIdentifierKind`, `AcmeIdentifier`, `AcmeOrderStatus`, `AcmeOrder`, `AcmeAuthzStatus`, `AcmeAuthorization`, `AcmeChallengeKind`, `AcmeChallengeStatus`, `AcmeChallenge`, `AcmeProblem`, `AcmeMsgLimits`, `AcmeMsgFault` | types only |
| `acmemsg.default_limits`, `.parse_directory`, `.parse_account`, `.parse_order`, `.parse_authorization`, `.parse_challenge`, `.parse_problem` | no |
| `acmemsg.write_new_account`, `.write_new_order`, `.write_finalize`, `.write_challenge_ready`, `.write_revoke`, `.write_deactivate` | no |
| `acmemsg.dns_identifier`, `.is_wildcard`, `.base_name`, `.identifier_for`, `.challenge_by_kind`, `.challenge_kind_of_name`, `.challenge_kind_name` | no |
| `acmemsg.is_terminal_order`, `.is_terminal_authz`, `.is_terminal_challenge` | no |
| `acmemsg.problem_is_bad_nonce`, `.problem_is_rate_limit`, `.problem_is_challenge_failure`, `.problem_kind`, `.problem_text`, the `message` impl | no |
| `acmejws` — `AcmeNonce`, `AcmeJwsKeyId`, `AcmeJwsFault` | types only |
| `acmejws.nonce`, `.nonce_value`, `.protected_header`, `.signing_input`, `.flattened`, `.signed_request`, `.algorithm_allowed` | no |
| `acmejws.jwk_of_ec`, `.thumbprint`, `.thumbprint_text`, `.key_authorization` | no |
| `acmejws.post_as_get_payload`, `.base64url`, `.base64url_decode`, the `message` impl | no |
| `acmechal` — `AcmeChalFault` | types only |
| `acmechal.ACME_DNS01_LABEL`, `.ACME_HTTP01_PREFIX`, `.ACME_HTTP01_PORT` | yes — they are constants |
| `acmechal.token_is_wellformed`, `.http01_path`, `.http01_body`, `.http01_url`, `.http01_content_type` | no |
| `acmechal.dns01_record_name`, `.dns01_record_value`, `.dns01_records_share_a_name`, `.dns01_names_for` | no |
| `acmechal.kind_can_answer`, `.preferred_challenge`, `.dns01_propagation_advice`, the `message` impl | no |
| `acmecsr` — `AcmeCsrFault`, `AcmeCsrScheme` | types only |
| `acmecsr.ACME_CSR_SUBJECT_IS_EMPTY` | yes — it is a constant |
| `acmecsr.csr_info`, `.csr`, `.csr_text`, `.names_of`, `.names_match`, `.first_name_disagreement` | no |
| `acmecsr.names_for_order`, `.name_is_wellformed`, `.scheme_oid_text`, `.signature_len_for`, the `message` impl | no |
| `acmerenew` — `AcmeRenewalPolicy`, `AcmeRenewalWindow`, `AcmeRenewFault` | types only |
| `acmerenew.ACME_RENEW_AT_NUMERATOR`, `.ACME_RENEW_AT_DENOMINATOR` | yes — they are constants |
| `acmerenew.default_policy`, `.with_fraction`, `.with_least_days_left`, `.with_window_hours`, `.renewal_window` | no |
| `acmerenew.should_renew`, `.days_left`, `.lifetime_days`, `.lifetime_used_percent` | no |
| `acmerenew.parse_timestamp`, `.order_expires_at`, `.authorization_expires_at`, `.order_needs_no_challenge`, `.poll_backoff_seconds`, the `message` impl | no |
| `acmeclient` — `AcmeSigner`, `AcmeSession`, `AcmeExchange`, `AcmeClientFault` | types only |
| `acmeclient.letsencrypt_directory_url`, `.letsencrypt_staging_directory_url`, `.signer`, `.session`, `.with_timeout`, `.with_user_agent` | no |
| `acmeclient.fresh_nonce`, `.post`, `.post_as_get` | no |
| `acmeclient.new_account`, `.find_account`, `.new_order`, `.authorization`, `.challenge_ready` | no |
| `acmeclient.poll_challenge`, `.poll_authorization`, `.poll_order` | no |
| `acmeclient.finalize`, `.download_certificate`, `.alternate_chains`, `.revoke`, `.deactivate_authorization` | no |
| `acmeclient.now_civil`, `.is_problem`, `.problem_of`, the `message` impl | no |
