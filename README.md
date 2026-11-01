# acme-nv

ACME is the protocol a server speaks to get a TLS certificate issued automatically. It is
specified in [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) and is what
Let's Encrypt and its successors implement. This package is an ACME client for
novo-lang: account creation, orders, the HTTP-01 and DNS-01 challenges,
certificate request generation, finalisation, certificate download, revocation,
and the arithmetic that says when to renew.

## What ACME is

A certificate authority will issue a certificate for a domain name only to
someone who can prove they control it. ACME turns that into a sequence of HTTP
requests.

1. **Fetch the directory.** One unauthenticated request returns the URLs of
   every other endpoint.
2. **Create an account.** The client generates a key pair and registers the
   public half. Every later request is signed with the private half.
3. **Place an order** for one or more domain names. The server answers with one
   *authorization* per name.
4. **Answer a challenge.** Each authorization offers several *challenges*, and
   the client picks one and satisfies it. HTTP-01 means serving a specific
   string at a specific path over plain HTTP. DNS-01 means publishing a specific
   TXT record.
5. **Tell the server the challenge is ready**, then poll until the
   authorization is valid.
6. **Finalise** by sending a certification request, and download the
   certificate.

Every request after the directory fetch is a *JSON Web Signature* (JWS): a
signed envelope whose protected header carries a server-issued *nonce* and the
URL being requested. The server checks the nonce, discards it, and returns a
fresh one in the reply's `Replay-Nonce` header. One nonce, one request, always.

The *key authorization* is the string that ties a challenge to an account key:
the challenge token, a dot, and the base64url of the SHA-256 thumbprint of the
account's public key (RFC 7638). HTTP-01 serves that string; DNS-01 publishes
its SHA-256, base64url-encoded.

## Install

```
novo pkg add acme-nv
```

## Example

```novo
use acmechal
use acmeclient
use acmejws
use acmemsg

// Publish the HTTP-01 answer.  Where it goes is a decision about a web
// server this package has never heard of, so the caller supplies it.
fn publish_http01(c: AcmeChallenge, jwk: Str, publish: fn(Str, Str) -> Bool) -> Bool
    match acmechal.http01_path(c.token)
        Err(_)   => false
        Ok(path) =>
            match acmechal.http01_body(c.token, jwk)
                Err(_)   => false
                Ok(body) => publish(path, body)

// Order a certificate for one name, proving control with HTTP-01.
//
// `sign` is a named function the caller supplies; see "Signing".
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
        None    => Err(AcmeClientBadMessage(AcmeMsgFieldMissing("challenges")))
        Some(c) =>
            if not publish_http01(c, jwk, publish)
                Err(AcmeClientTransportFailed("the challenge could not be published"))
            else
                let told = acmeclient.challenge_ready(registered.0, got.1, c.url)!
                Ok(told.0.url)
```

Build and test with:

```
novo pkg build               # type- and effect-check the package
novo test tests/acmemsg_tests.nv
bash tests/coverage.sh       # every suite, and the line coverage of src/
```

`tests/acmeclient_tests.nv` needs `python3` with the `cryptography`
package. It starts a small ACME server on the loopback interface and
talks to nothing else. The server verifies every signature, rebuilds
every key authorization and parses every certification request with
its own code, so a request this client gets wrong is refused by
something other than this client.

## What the package contains

| Module | Contents | Performs input or output |
| --- | --- | --- |
| `acmemsg` | The objects an ACME server serves, as values: the directory, the account, the order, the authorization, the challenge and the problem document, with a parser and a writer for each. | no |
| `acmejws` | The signing envelope: the protected header, the signing input, the flattened JSON serialisation, the JWK and its thumbprint, the key authorization, and base64url in both directions. | no |
| `acmechal` | The four values a caller publishes to answer a challenge: the HTTP-01 path and body, and the DNS-01 record name and value. | no |
| `acmecsr` | The certification request: PKCS#10 built over asn1-nv, and the checks that its names match the order's. | no |
| `acmerenew` | When to renew: the policy, the renewal window, the day arithmetic, and the poll backoff schedule. "Now" is an argument. | no |
| `acmeclient` | The requests. Every function here declares `[io, net, time, async]`, which is what the standard library's HTTP client declares. | yes |

`acmeclient.now_civil` reads a clock and declares `[time]`. It is the one clock
read the package makes for its own sake.

## How to choose an entry point

**A program that wants a certificate calls `acmeclient`.** Start with
`acmeclient.session`, get a nonce with `fresh_nonce`, and thread it through the
calls in the order above.

**A program that already has an HTTP client calls the other five modules
directly.** `acmemsg` parses and writes every message body, `acmejws` builds and
signs the envelope, and neither performs any input or output. That is the whole
protocol minus the transport.

**A program that only needs to know when to renew calls `acmerenew`.**
`should_renew` takes the certificate's validity dates and the current time and
answers a boolean.

## The rules a user needs

1. **A nonce is used once.** It is a value threaded through the calls, not a
   field the session updates.

   ```novo ignore
   let ordered = acmeclient.new_order(session, nonce, identifiers)!
   // ordered.1 is the NEXT nonce; the one above it is spent.
   ```

   A client that sent two requests from one nonce gets `badNonce` on the second,
   and only under load, because a server that is not busy is more forgiving
   about near-simultaneous requests.
2. **`badNonce` is retried here, once, automatically.** RFC 8555 section 6.5
   says a client that receives one MUST retry the same request with the nonce
   from that very reply, so it is not an error a caller should see. A *second*
   `badNonce` for the same request is surfaced as
   `AcmeClientNonceRetryExhausted(url)`, because two in succession mean a clock
   skew or a client that is not following the protocol.
3. **There is no `get` in this package.** RFC 8555 section 6.3 replaced GET with
   POST-as-GET: a signed POST whose payload is zero bytes.
   `acmeclient.post_as_get` is how every object is read. The empty payload is
   not `{}`: on a challenge URL `{}` means "start validating", which is why
   `acmejws.post_as_get_payload` and `acmemsg.write_challenge_ready` are two
   named functions and neither is a default.
4. **The JWK thumbprint is over a canonical JSON string.** RFC 7638 requires
   only the members the key type needs, member names in lexicographic order, and
   no whitespace. For a P-256 key that is exactly
   `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`. One extra member, one different
   order, one space, and the thumbprint changes, so the key authorization
   changes, so every challenge fails with a message about the response not
   matching. `acmejws.jwk_of_ec` produces the canonical form and
   `acmejws.thumbprint` is the only thing that hashes it.
5. **The HTTP-01 body is the key authorization exactly, with no trailing
   newline.** A shell redirect adds one. RFC 8555 section 8.3 says a server
   SHOULD ignore trailing whitespace, and SHOULD is why this is still the
   commonest way an HTTP-01 challenge fails.
6. **A wildcard's DNS-01 record name is the base name's.** The record for
   `*.example.com` is `_acme-challenge.example.com`, the same name as for
   `example.com` itself. An order for both therefore needs **two TXT values at
   one name**, and a DNS provider API call that *replaces* a record set rather
   than adding to it invalidates the first challenge when it publishes the
   second. `acmechal.dns01_records_share_a_name` is the predicate that says so,
   and `acmechal.dns01_names_for` answers the deduplicated list.
7. **The signature is encoded two different ways in one issuance.** A JWS
   signature is the fixed-width `r || s`, which is 64 bytes for ES256. A
   certification request's signature is the DER `SEQUENCE { r, s }`. Same key,
   same algorithm, two encodings. asn1-nv's `ecdsa_signature_rs` and
   `ecdsa_signature_der` convert between them, and a client that used one form
   for both has one of the two refused with a message about an invalid
   signature.
8. **A token is checked before it becomes a path.** `acmechal.token_is_wellformed`
   rejects any character outside base64url's alphabet, and
   `AcmeChalTokenNotWellformed(at)` names the position. RFC 8555 section 11.3's
   entropy floor is checked too, as `AcmeChalTokenTooShort(length, least)`.
9. **A reply with no `Replay-Nonce` is a distinct failure**,
   `AcmeClientNoNonce(url)`, because the recovery differs: fetch a fresh nonce
   rather than retry. A `newAccount` or `newOrder` reply with no `Location`
   header is `AcmeClientNoLocation(url)`, since the object then has no URL.

## Signing

The account key signs with ECDSA over P-256, and
[p256-nv](https://novo-lang.org/packages/p256-nv) supplies `ecdsa_sign`.
jwt-nv publishes the key vocabulary, `JwtAlg`, `JwtSigningKey` and
`ec_signing_key`, but no function that signs arbitrary bytes. An ACME
request is the flattened JSON serialisation over a protected header with a
nonce and a URL in it, which is not a claims set, so `jwttoken.encode` is
the wrong shape.

So `acmejws.signed_request` and `acmeclient.signer` take the signing
function as an argument: a named function from the bytes to sign to the
64-byte `r || s`, or `None` when it declines. That also suits a caller
whose account key lives in a hardware token or a cloud key service, who
supplies a function and never holds the key. For an in-memory key the
function is a few lines:

```novo ignore
use std.bytes
use hashing
use p256

fn sign_with_account(input: Bytes) -> ?Bytes
    match p256.secret_key_from_bytes(account_secret)
        Err(_) => None
        Ok(sk) =>
            match p256.ecdsa_sign(sk, bytes.to_byte_list(hashing.sha256(input)))
                Err(_)  => None
                Ok(sig) => Some(bytes.from_byte_list(sig))
```

The certification request is signed over the bytes `acmecsr.csr_info`
returns, and its signature is the DER form, which `asn1pkix.ecdsa_signature_der`
makes from `r` and `s`.

## What is not included

- **Serving the challenge.** An HTTP-01 challenge is a file at a path, and where
  that file goes depends on whether the caller runs a web server, a reverse
  proxy, a static host, or nothing at all on port 80.
  `acmechal.http01_path` and `.http01_body` are the two values; putting them
  somewhere is the caller's job.
- **Updating DNS.** A DNS-01 challenge is a TXT record, and publishing one is an
  API call to whichever provider holds the zone.
  `acmechal.dns01_record_name` and `.dns01_record_value` are the two values.
- **Polling and sleeping.** `poll_order`, `poll_authorization` and
  `poll_challenge` each perform exactly one request. The loop, the backoff and
  the deadline are the caller's, with `acmerenew.poll_backoff_seconds` as the
  schedule. A library that ran its own loop would own a timeout policy for a
  process it knows nothing about, and would hide the one thing an operator
  watching an issuance wants to see.
- **Storage.** No account key on disk, no certificate written, no state file.
  `acmerenew` says *when* to renew; where the certificate and the key live is
  the program's business.
- **TLS-ALPN-01.** That challenge is answered during a TLS handshake with a
  certificate carrying a specific extension, so it needs a TLS server that can
  be told to present one. `AcmeTlsAlpn01` exists as a value so a challenge list
  round-trips, and `acmechal.kind_can_answer` answers false for it.
- **External account binding.** A commercial CA that requires one needs an HMAC
  over the account key with a key issued out of band.
  `AcmeDirectory.external_account_required` says when a server wants it.
- **Key generation.** An account key and a certificate key come from p256-nv's
  `key_pair_from_random`, whose randomness is the caller's.
- **A build for a microcontroller with no heap allocator.** This package speaks
  HTTP.

## Related packages

| Package | What it supplies |
| --- | --- |
| jwt-nv | `JwtAlg`, `JwtSigningKey` and `ec_signing_key`: the key vocabulary an ACME signature is made with. |
| [p256-nv](https://novo-lang.org/packages/p256-nv) | The account key and the certificate key, and the ECDSA signing that uses them. |
| asn1-nv | `AsnName`, `AsnExtension`, the subjectAltName object identifier, `write_spki` and `ecdsa_signature_der`. `acmecsr` builds PKCS#10 out of these and encodes no DER of its own. |
| [crypto-nv](https://novo-lang.org/packages/crypto-nv) | SHA-256, for the JWK thumbprint and for the DNS-01 record's value. |
| base64-nv | base64url without padding, which is every encoded field in a JWS and the certification request in a finalise payload. ACME uses the URL alphabet with the padding stripped everywhere, and a client that sent standard base64 has its signature refused with no useful message. |
| calendar-nv | Civil dates and time deltas, for renewal planning and for reading the RFC 3339 timestamps an order and an authorization carry. |

## The reference implementation

`instant-acme` (Rust) is the reference for the shape. Its split into account,
order and authorization, and its decision to hand the challenge values back to
the caller rather than serving them, are both ported directly. `certbot` is the
reference for the operational surface: the staging directory named beside the
production one, the renewal fraction, and the insistence that a failed
challenge's `detail` field is the only useful thing in a failure.

RFC 8555 is the specification. RFC 7638 defines the thumbprint, RFC 7515 and
RFC 7517 the JWS and the JWK, and RFC 2986 the certification request.

Three things differ from `instant-acme`.

It keeps the current nonce inside the account object and refreshes it
internally. Here the nonce is a value the caller threads, so the single-use rule
is in the types rather than in a comment.

It signs with `ring` behind a signer trait it owns. Here the signing function is
an argument, so a key held outside the process signs as easily as one in memory.

And certbot's plugin architecture — what lets it publish an HTTP-01 challenge
through nginx or a DNS-01 challenge through fifty providers — is not ported. The
four strings this package produces, handed to a caller that knows its own
infrastructure, do the same work.

## Licence

Apache-2.0. See `LICENSE`.
