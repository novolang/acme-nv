# A small ACME server for the network tests, in the shape of Pebble: a
# directory, nonces, accounts, orders with one authorization each,
# HTTP-01 and DNS-01 challenges, finalisation against a real PKCS#10
# parser, certificate download with alternate chains, revocation and
# deactivation.  It binds an ephemeral port on 127.0.0.1 and prints it
# as the first line.  Run with `python3 -I acme_double.py`.
#
# Every check here is the independent oracle for what the client puts
# on the wire: the JWS signature is verified with the `cryptography`
# package, the key authorization is rebuilt with `hashlib`, and the
# certification request is parsed and verified by `cryptography`'s
# x509 reader, so a client that gets any encoding wrong is refused by
# something that is not this package.
import base64, datetime, hashlib, json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

ERR = "urn:ietf:params:acme:error:"
lock = threading.RLock()
state = {
    "nonces": set(), "accounts": {}, "orders": {}, "authzs": {}, "chals": {}, "certs": {},
    "revoked": [], "log": [], "counter": 0,
    "http01": {}, "dns01": {},
    # fault injection, set through POST /ctl/set
    "ctl": {"bad_nonce": 0, "rate_limit": 0, "omit_nonce": 0, "omit_location": 0,
            "cached_authz": 0, "fail_validation": 0, "no_finalize_location": 0, "garbage": 0},
}

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

CA_KEY = ec.generate_private_key(ec.SECP256R1())
CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acme-double test CA")])
NOW = datetime.datetime.utcnow()
CA_CERT = (x509.CertificateBuilder().subject_name(CA_NAME).issuer_name(CA_NAME)
           .public_key(CA_KEY.public_key()).serial_number(1)
           .not_valid_before(NOW - datetime.timedelta(days=1))
           .not_valid_after(NOW + datetime.timedelta(days=3650))
           .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
           .sign(CA_KEY, hashes.SHA256()))

def jwk_thumbprint(jwk):
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
                       separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(canon.encode()).digest())

def key_authorization(chal):
    return chal["token"] + "." + jwk_thumbprint(state["accounts"][chal["account"]]["jwk"])

class Problem(Exception):
    def __init__(self, status, kind, detail, extra=None):
        self.status, self.kind, self.detail, self.extra = status, ERR + kind, detail, extra or {}

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass

    def base(self): return "http://127.0.0.1:%d" % self.server.server_port

    def reply(self, status, body=b"", ctype="application/json", headers=None, nonce=True):
        if isinstance(body, str): body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if nonce and not state["ctl"]["omit_nonce"]:
            n = b64u(os.urandom(16))
            with lock: state["nonces"].add(n)
            self.send_header("Replay-Nonce", n)
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def problem(self, p):
        body = {"type": p.kind, "detail": p.detail, "status": p.status}
        body.update(p.extra)
        hdr = [("Retry-After", "7")] if p.kind.endswith("rateLimited") else []
        self.reply(p.status, json.dumps(body), "application/problem+json", hdr)

    def do_HEAD(self): self.dispatch("HEAD")
    def do_GET(self): self.dispatch("GET")
    def do_POST(self): self.dispatch("POST")

    def dispatch(self, method):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        path = self.path
        with lock: state["log"].append([method, path])
        try:
            if path.startswith("/ctl/"): return self.control(method, path, raw)
            if path == "/directory" and method == "GET": return self.directory()
            if path == "/nonce" and method in ("HEAD", "GET"):
                return self.reply(200 if method == "HEAD" else 204, b"", "text/plain",
                                  [("Cache-Control", "no-store")])
            if method != "POST":
                raise Problem(405, "malformed", "method not allowed: every read is a POST-as-GET")
            self.acme_post(path, raw)
        except Problem as p:
            self.problem(p)

    # ── control ──────────────────────────────────────────────────────
    def control(self, method, path, raw):
        if path == "/ctl/set":
            with lock: state["ctl"].update(json.loads(raw))
            return self.reply(200, "{}", nonce=False)
        if path == "/ctl/log":
            with lock: out = json.dumps(state["log"])
            return self.reply(200, out, nonce=False)
        if path == "/ctl/reset-log":
            with lock: state["log"] = []
            return self.reply(200, "{}", nonce=False)
        if path.startswith("/ctl/http01/"):
            with lock: state["http01"][path.rsplit("/", 1)[1]] = raw.decode()
            return self.reply(200, "{}", nonce=False)
        if path.startswith("/ctl/dns01/"):
            with lock: state["dns01"].setdefault(path.rsplit("/", 1)[1], []).append(raw.decode())
            return self.reply(200, "{}", nonce=False)
        if path.startswith("/ctl/keyauth/"):
            with lock: chal = state["chals"][path.rsplit("/", 1)[1]]
            return self.reply(200, key_authorization(chal), "text/plain", nonce=False)
        if path.startswith("/ctl/chain/"):
            with lock: return self.reply(200, state["certs"][path.rsplit("/", 1)[1]]["pem"], "text/plain", nonce=False)
        if path == "/ctl/plain500":
            return self.reply(500, "oops, not an ACME server", "text/plain")
        self.reply(404, "{}", nonce=False)

    def directory(self):
        b = self.base()
        self.reply(200, json.dumps({
            "newNonce": b + "/nonce", "newAccount": b + "/acct", "newOrder": b + "/order",
            "revokeCert": b + "/revoke", "keyChange": b + "/key-change",
            "meta": {"termsOfService": b + "/terms", "website": b, "caaIdentities": ["double.test"],
                     "externalAccountRequired": False}}), nonce=False)

    # ── JWS ──────────────────────────────────────────────────────────
    def verify_jws(self, raw):
        try:
            body = json.loads(raw)
        except Exception:
            raise Problem(400, "malformed", "the body is not JSON")
        if set(body.keys()) != {"protected", "payload", "signature"}:
            raise Problem(400, "malformed", "the body is not the flattened JWS serialisation")
        for k in ("protected", "payload", "signature"):
            if "=" in body[k]:
                raise Problem(400, "malformed", k + " is padded base64url")
        prot = json.loads(unb64u(body["protected"]))
        if prot.get("alg") != "ES256":
            raise Problem(400, "badSignatureAlgorithm", "alg must be ES256")
        if ("jwk" in prot) == ("kid" in prot):
            raise Problem(400, "malformed", "exactly one of jwk and kid is required")
        if prot.get("url") != self.base() + self.path:
            raise Problem(401, "unauthorized", "the signed url does not match the request url")
        nonce = prot.get("nonce")
        with lock:
            ctl = state["ctl"]
            if ctl["bad_nonce"] > 0:
                ctl["bad_nonce"] -= 1
                raise Problem(400, "badNonce", "JWS has an invalid anti-replay nonce")
            if nonce not in state["nonces"]:
                raise Problem(400, "badNonce", "JWS has an invalid anti-replay nonce")
            state["nonces"].discard(nonce)
            if ctl["rate_limit"] > 0:
                ctl["rate_limit"] -= 1
                raise Problem(429, "rateLimited", "too many requests")
        if "jwk" in prot:
            jwk = prot["jwk"]
            if set(jwk.keys()) != {"crv", "kty", "x", "y"} or jwk["kty"] != "EC" or jwk["crv"] != "P-256":
                raise Problem(400, "badPublicKey", "unsupported jwk")
            account = None
        else:
            account = prot["kid"].rsplit("/", 1)[1]
            if account not in state["accounts"]:
                raise Problem(400, "accountDoesNotExist", "no such account")
            jwk = state["accounts"][account]["jwk"]
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64u(jwk["x"]), "big"),
                                            int.from_bytes(unb64u(jwk["y"]), "big"),
                                            ec.SECP256R1()).public_key()
        sig = unb64u(body["signature"])
        if len(sig) != 64:
            raise Problem(400, "malformed", "an ES256 signature is 64 bytes, r then s")
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        try:
            pub.verify(der, (body["protected"] + "." + body["payload"]).encode(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise Problem(400, "malformed", "JWS verification error")
        payload = unb64u(body["payload"]).decode()
        return prot, jwk, account, payload

    # ── the ACME endpoints ───────────────────────────────────────────
    def acme_post(self, path, raw):
        prot, jwk, account, payload = self.verify_jws(raw)
        b = self.base()
        with lock:
            garbage = state["ctl"]["garbage"] > 0
            if garbage: state["ctl"]["garbage"] -= 1
        if garbage:
            return self.reply(201, json.dumps({"status": "sleeping"}), headers=[("Location", b + "/order/0")])
        if path == "/acct":
            if account is not None:
                raise Problem(400, "malformed", "newAccount is signed with a jwk, not a kid")
            req = json.loads(payload)
            tp = jwk_thumbprint(jwk)
            with lock:
                found = [k for k, v in state["accounts"].items() if jwk_thumbprint(v["jwk"]) == tp]
                if req.get("onlyReturnExisting"):
                    if not found:
                        raise Problem(400, "accountDoesNotExist", "no account for this key")
                    return self.send_account(found[0], 200)
                if found:
                    return self.send_account(found[0], 200)
                if not req.get("termsOfServiceAgreed"):
                    raise Problem(403, "userActionRequired", "terms of service must be agreed",
                                  {"instance": b + "/terms"})
                state["counter"] += 1
                aid = str(state["counter"])
                state["accounts"][aid] = {"jwk": jwk, "contact": req.get("contact", [])}
            return self.send_account(aid, 201)
        if account is None and path != "/revoke":
            raise Problem(400, "malformed", "this request is signed with a kid")
        if path == "/order":
            req = json.loads(payload)
            ids = req["identifiers"]
            if not ids or any(i["type"] != "dns" for i in ids):
                raise Problem(400, "rejectedIdentifier", "only dns identifiers")
            with lock:
                state["counter"] += 1
                oid = str(state["counter"])
                azs = []
                seen = []
                for i in ids:
                    wild = i["value"].startswith("*.")
                    base = i["value"][2:] if wild else i["value"]
                    if (base, wild) in seen:
                        continue
                    seen.append((base, wild))
                    state["counter"] += 1
                    zid = str(state["counter"])
                    chals = []
                    kinds = ["dns-01"] if wild else ["http-01", "dns-01"]
                    for kind in kinds:
                        state["counter"] += 1
                        cid = str(state["counter"])
                        state["chals"][cid] = {"id": cid, "type": kind, "status": "pending",
                                               "token": b64u(os.urandom(32)), "authz": zid,
                                               "account": account, "domain": base}
                        chals.append(cid)
                    cached = state["ctl"]["cached_authz"] > 0
                    state["authzs"][zid] = {"id": zid, "domain": base, "wild": wild, "chals": chals,
                                            "status": "valid" if cached else "pending"}
                    azs.append(zid)
                if state["ctl"]["cached_authz"] > 0:
                    state["ctl"]["cached_authz"] -= 1
                state["orders"][oid] = {"id": oid, "account": account, "ids": ids, "authzs": azs,
                                        "status": "pending", "cert": None}
            return self.send_order(oid, 201)
        if path.startswith("/order/") and path.endswith("/finalize"):
            return self.finalize(path.split("/")[2], payload)
        if path.startswith("/order/"):
            self.require_empty(payload)
            return self.send_order(path.split("/")[2], 200)
        if path.startswith("/authz/"):
            zid = path.split("/")[2]
            with lock: az = state["authzs"].get(zid)
            if az is None: raise Problem(404, "malformed", "no such authorization")
            if payload != "":
                req = json.loads(payload)
                if req.get("status") != "deactivated":
                    raise Problem(400, "malformed", "only a POST-as-GET or a deactivation")
                with lock: az["status"] = "deactivated"
            return self.send_authz(zid)
        if path.startswith("/chall/"):
            return self.challenge(path.split("/")[2], payload)
        if path.startswith("/cert/"):
            self.require_empty(payload)
            cid = path.split("/")[2]
            with lock: cert = state["certs"].get(cid)
            if cert is None: raise Problem(404, "malformed", "no such certificate")
            links = [("Link", '<%s/directory>;rel="index"' % b),
                     ("Link", '<%s/cert/%s-alt1>;rel="alternate", <%s/cert/%s-alt2>;rel="alternate"' % (b, cid, b, cid))]
            return self.reply(200, cert["pem"], "application/pem-certificate-chain", links)
        if path == "/revoke":
            req = json.loads(payload)
            der = unb64u(req["certificate"])
            cert = x509.load_der_x509_certificate(der)
            with lock: state["revoked"].append([cert.serial_number, req.get("reason", 0)])
            return self.reply(200, b"", "application/json")
        raise Problem(404, "malformed", "no such endpoint " + path)

    def require_empty(self, payload):
        if payload != "":
            raise Problem(400, "malformed", "a read is a POST-as-GET with an empty payload, not " + repr(payload))

    def send_account(self, aid, status):
        b = self.base()
        a = state["accounts"][aid]
        hdr = [] if state["ctl"]["omit_location"] else [("Location", b + "/acct/" + aid)]
        self.reply(status, json.dumps({"status": "valid", "contact": a["contact"],
                                       "termsOfServiceAgreed": True, "orders": b + "/acct/" + aid + "/orders"}),
                   headers=hdr)

    def order_status(self, o):
        if o["status"] in ("valid", "invalid", "processing"):
            return o["status"]
        sts = [state["authzs"][z]["status"] for z in o["authzs"]]
        if any(s in ("invalid", "deactivated", "expired", "revoked") for s in sts): return "invalid"
        return "ready" if all(s == "valid" for s in sts) else "pending"

    def order_json(self, o):
        b = self.base()
        o["status"] = self.order_status(o)
        out = {"status": o["status"], "expires": "2099-01-01T00:00:00Z",
               "identifiers": o["ids"], "authorizations": [b + "/authz/" + z for z in o["authzs"]],
               "finalize": b + "/order/" + o["id"] + "/finalize"}
        if o["cert"]: out["certificate"] = b + "/cert/" + o["cert"]
        if o["status"] == "invalid":
            out["error"] = {"type": ERR + "unauthorized", "detail": "an authorization failed", "status": 403}
        return out

    def send_order(self, oid, status):
        with lock:
            o = state["orders"].get(oid)
            if o is None: raise Problem(404, "malformed", "no such order")
            body = self.order_json(o)
        hdr = [] if state["ctl"]["omit_location"] else [("Location", self.base() + "/order/" + oid)]
        self.reply(status, json.dumps(body), headers=hdr)

    def send_authz(self, zid):
        b = self.base()
        with lock:
            az = state["authzs"][zid]
            out = {"identifier": {"type": "dns", "value": az["domain"]}, "status": az["status"],
                   "expires": "2099-01-01T00:00:00Z", "challenges": [
                       self.chal_json(c) for c in az["chals"]]}
            if az["wild"]: out["wildcard"] = True
        self.reply(200, json.dumps(out))

    def chal_json(self, cid):
        c = state["chals"][cid]
        out = {"type": c["type"], "url": self.base() + "/chall/" + cid, "status": c["status"], "token": c["token"]}
        if c["status"] == "valid": out["validated"] = "2026-01-01T00:00:00Z"
        if c["status"] == "invalid":
            out["error"] = {"type": ERR + "unauthorized", "status": 403,
                            "detail": "Invalid response from http://%s/.well-known/acme-challenge/%s: 404" % (c["domain"], c["token"])}
        return out

    def challenge(self, cid, payload):
        with lock:
            c = state["chals"].get(cid)
            if c is None: raise Problem(404, "malformed", "no such challenge")
            if payload == "{}":
                # The client says the challenge is ready: validate against what the test published.
                expected = key_authorization(c)
                if c["type"] == "http-01":
                    got = state["http01"].get(c["token"])
                    ok = got == expected
                else:
                    want = b64u(hashlib.sha256(expected.encode()).digest())
                    ok = want in state["dns01"].get("_acme-challenge." + c["domain"], [])
                if state["ctl"]["fail_validation"] > 0:
                    state["ctl"]["fail_validation"] -= 1
                    ok = False
                c["status"] = "valid" if ok else "invalid"
                az = state["authzs"][c["authz"]]
                az["status"] = "valid" if ok else "invalid"
            elif payload != "":
                raise Problem(400, "malformed", "a challenge takes {} or a POST-as-GET")
            body = self.chal_json(cid)
        self.reply(200, json.dumps(body), headers=[("Link", '<%s/authz/%s>;rel="up"' % (self.base(), c["authz"]))])

    def finalize(self, oid, payload):
        req = json.loads(payload)
        with lock:
            o = state["orders"].get(oid)
            if o is None: raise Problem(404, "malformed", "no such order")
            if self.order_status(o) != "ready":
                raise Problem(403, "orderNotReady", "the order is not ready")
            der = unb64u(req["csr"])
            try:
                csr = x509.load_der_x509_csr(der)
            except Exception as e:
                raise Problem(400, "badCSR", "unparseable CSR: %s" % e)
            if not csr.is_signature_valid:
                raise Problem(400, "badCSR", "CSR signature is invalid")
            try:
                san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                names = sorted(san.get_values_for_type(x509.DNSName))
            except x509.ExtensionNotFound:
                raise Problem(400, "badCSR", "CSR has no subjectAltName")
            want = sorted({i["value"] for i in o["ids"]})
            if names != want:
                raise Problem(400, "badCSR", "CSR names %s do not match order names %s" % (names, want))
            if len(csr.subject) != 0:
                raise Problem(400, "badCSR", "the subject is expected to be empty")
            state["counter"] += 1
            cid = str(state["counter"])
            cert = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(CA_NAME)
                    .public_key(csr.public_key()).serial_number(1000 + state["counter"])
                    .not_valid_before(NOW).not_valid_after(NOW + datetime.timedelta(days=90))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=True)
                    .sign(CA_KEY, hashes.SHA256()))
            pem = (cert.public_bytes(serialization.Encoding.PEM) + CA_CERT.public_bytes(serialization.Encoding.PEM)).decode()
            state["certs"][cid] = {"pem": pem}
            o["status"] = "valid"
            o["cert"] = cid
            body = self.order_json(o)
        hdr = [] if state["ctl"]["no_finalize_location"] else [("Location", self.base() + "/order/" + oid)]
        self.reply(200, json.dumps(body), headers=hdr)

if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    print(srv.server_port, flush=True)
    threading.Timer(600, lambda: os._exit(0)).start()
    srv.serve_forever()
