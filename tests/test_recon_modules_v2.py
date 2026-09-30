"""Offline unit tests for the ten v2 recon modules.

Every test in this file is hermetic. The resolver and the HTTP client are
replaced with explicit fakes at the exact seam each module uses, so no socket is
opened and no name is resolved against a real server - which also means the
assertions are deterministic rather than dependent on what the internet happens
to answer today.

The tests are grouped per module and each group covers three things:

1. a happy path asserting the module's documented key set and parsed values,
2. a failure/absence path proving the module never raises, and
3. the correctness rule that module exists to enforce - the tri-state
   present/lookup_failed distinction for the DNS modules, the 404-is-not-an-error
   and refusal-is-not-a-listing rules for reputation, the wildcard and catch-all
   false-positive filters, the content-verification guard, and the
   ``alt-svc``-absent-is-None rule.
"""

import base64
import json
import unittest
from types import SimpleNamespace
from urllib.parse import urlsplit
from unittest.mock import MagicMock, patch

import httpx

from core import asn_intel, cloud_buckets, dns_deep, email_auth, exposure
from core import http_protocol, reputation, sri, subdomain_brute, vhost
from core.risk import score_result


# ---------------------------------------------------------------------------
# Shared fakes. These stand in for dnspython rdata and for httpx responses so
# the modules under test never touch the network.
# ---------------------------------------------------------------------------
class _Rdata:
    """Attribute-bearing rdata stand-in (CAA / SRV / NS records)."""

    def __init__(self, **fields):
        self.__dict__.update(fields)

    def __str__(self):
        return str(self.__dict__.get("text", ""))


def _text_rdata(text):
    """rdata whose ``str()`` is the record text (DS / DNSKEY / A records)."""
    return _Rdata(text=text)


def _response(status=200, body="", headers=None, http_version="HTTP/1.1", extensions=None):
    """A minimal httpx.Response stand-in exposing exactly what the modules read."""
    response = MagicMock()
    response.status_code = status
    response.content = body.encode("utf-8") if isinstance(body, str) else body
    response.text = body if isinstance(body, str) else body.decode("utf-8", "replace")
    response.headers = headers if headers is not None else {}
    response.http_version = http_version
    response.extensions = extensions if extensions is not None else {}
    return response


def _client(get_return=None, get_side_effect=None):
    """A stand-in httpx.Client usable both as ``with Client() as c`` and ``c = Client()``."""
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    if get_side_effect is not None:
        client.get.side_effect = get_side_effect
    else:
        client.get.return_value = get_return
    return client


class DnsDeepTests(unittest.TestCase):
    """core.dns_deep - tri-state presence, and refusals are not errors."""

    _KEYS = {
        "domain", "caa", "caa_present", "srv", "ds", "dnskey_count", "dnssec_signed",
        "ns", "axfr", "wildcard", "issues", "errors",
    }

    @patch("dns.query.xfr", side_effect=Exception("REFUSED"))
    @patch("core.dns_deep._query")
    def test_happy_path_reports_documented_keys(self, query, xfr):
        def fake_query(host, rtype, timeout):
            if host.startswith("inoue-wildcard-"):
                return [], "absent"
            if rtype == "CAA":
                return [_Rdata(flags=0, tag="issue", value="letsencrypt.org")], "ok"
            if rtype == "SRV":
                return [_Rdata(priority=10, weight=5, port=5060, target="sip.example.com.")], "ok"
            if rtype == "DS":
                return [_text_rdata("2371 13 2 c988ec423e3880eb8dd8a46fe06ca230")], "ok"
            if rtype == "DNSKEY":
                return [_text_rdata("256 3 13 xyz")], "ok"
            if rtype == "NS":
                return [_Rdata(target="ns1.example.com.")], "ok"
            if rtype == "A":
                return [_text_rdata("203.0.113.10")], "ok"
            return [], "absent"

        query.side_effect = fake_query
        result = dns_deep.analyze("Example.COM.")

        self.assertEqual(set(result), self._KEYS)
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["caa"], [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}])
        self.assertTrue(result["caa_present"])
        self.assertIn("_sip._tcp.example.com", result["srv"])
        self.assertEqual(result["srv"]["_sip._tcp.example.com"][0]["target"], "sip.example.com")
        self.assertEqual(result["ds"], ["2371 13 2 c988ec423e3880eb8dd8a46fe06ca230"])
        self.assertEqual(result["dnskey_count"], 1)
        self.assertTrue(result["dnssec_signed"])
        self.assertEqual(result["ns"], [{"host": "ns1.example.com", "ips": ["203.0.113.10"]}])
        self.assertFalse(result["wildcard"]["detected"])
        self.assertEqual(result["errors"], [])

    @patch("core.dns_deep._query", return_value=([], "failed"))
    def test_lookup_timeout_is_never_reported_as_an_absent_record(self, query):
        """Regression guard: a DNS timeout must not become 'No CAA record
        published - any CA may issue certificates', which is a confidently
        wrong security claim."""
        result = dns_deep.analyze("example.com")

        self.assertIsNone(result["caa_present"])
        self.assertTrue(result["errors"])
        self.assertEqual(result["issues"], [])
        self.assertFalse(any("No CAA record published" in issue for issue in result["issues"]))

    @patch("core.dns_deep._query", return_value=([], "absent"))
    def test_genuine_absence_is_reported_as_absent(self, query):
        """The other half of the rule: a completed lookup with no answer *is*
        an established absence and must be reported as one."""
        result = dns_deep.analyze("example.com")

        self.assertFalse(result["caa_present"])
        self.assertTrue(any("No CAA record published" in issue for issue in result["issues"]))
        self.assertEqual(result["errors"], [])

    @patch("dns.query.xfr", side_effect=Exception("TransferError: REFUSED"))
    @patch("core.dns_deep._query")
    def test_refused_zone_transfer_is_not_an_error(self, query, xfr):
        def fake_query(host, rtype, timeout):
            if rtype == "NS":
                return [_Rdata(target="ns1.example.com.")], "ok"
            if rtype == "A":
                return [_text_rdata("203.0.113.10")], "ok"
            return [], "absent"

        query.side_effect = fake_query
        result = dns_deep.analyze("example.com")

        self.assertTrue(result["axfr"]["attempted"])
        self.assertFalse(result["axfr"]["allowed"])
        self.assertEqual(result["axfr"]["errors"], [])
        self.assertEqual(result["errors"], [])
        self.assertFalse(any("AXFR" in issue for issue in result["issues"]))

    @patch("dns.zone.from_xfr")
    @patch("dns.query.xfr")
    @patch("core.dns_deep._query")
    def test_allowed_zone_transfer_is_surfaced_loudly(self, query, xfr, from_xfr):
        def fake_query(host, rtype, timeout):
            if rtype == "NS":
                return [_Rdata(target="ns1.example.com.")], "ok"
            if rtype == "A":
                return [_text_rdata("203.0.113.10")], "ok"
            return [], "absent"

        query.side_effect = fake_query
        xfr.return_value = MagicMock()
        node = MagicMock()
        node.rdatasets = [["r1", "r2"]]
        zone = MagicMock()
        zone.nodes = {"www": node}
        from_xfr.return_value = zone

        result = dns_deep.analyze("example.com")

        self.assertTrue(result["axfr"]["allowed"])
        self.assertEqual(result["axfr"]["records"], 2)
        self.assertTrue(any("Zone transfer (AXFR) ALLOWED" in issue for issue in result["issues"]))

    @patch("core.dns_deep._query", return_value=([], "absent"))
    def test_malformed_input_never_raises(self, query):
        for value in ("", "   ", None, ".", "not a domain!!"):
            result = dns_deep.analyze(value)
            self.assertEqual(set(result), self._KEYS)


    @patch("core.dns_deep._query")
    def test_dnssec_timeout_is_unknown_not_unsigned(self, query):
        """Regression guard: a DS/DNSKEY timeout must not be reported as a
        definitive 'not signed'. The same call already appends 'DNSSEC status is
        NOT established' to errors, so the flag has to be None, not False."""
        def fake_query(host, rtype, timeout):
            if rtype in ("DS", "DNSKEY"):
                return [], "failed"
            return [], "absent"

        query.side_effect = fake_query
        result = dns_deep.analyze("example.com")

        self.assertIsNone(result["dnssec_signed"])
        self.assertTrue(any("DNSSEC status is NOT established" in error for error in result["errors"]))

    @patch("core.dns_deep._query", return_value=([], "absent"))
    def test_dnssec_completed_but_empty_is_definitively_unsigned(self, query):
        """The other half of the rule: when every lookup completed and found
        nothing, 'not signed' is an established fact and must be reported."""
        result = dns_deep.analyze("example.com")

        self.assertIs(result["dnssec_signed"], False)
        self.assertEqual(result["errors"], [])

    @patch("core.dns_deep._query")
    def test_dnssec_partial_failure_with_material_is_still_signed(self, query):
        """A positive answer settles the question even if the other lookup timed
        out, because the zone demonstrably publishes DNSSEC material."""
        def fake_query(host, rtype, timeout):
            if rtype == "DS":
                return [], "failed"
            if rtype == "DNSKEY":
                return [_text_rdata("256 3 13 xyz")], "ok"
            return [], "absent"

        query.side_effect = fake_query
        result = dns_deep.analyze("example.com")

        self.assertIs(result["dnssec_signed"], True)


class EmailAuthTests(unittest.TestCase):
    """core.email_auth - tri-state presence behind SPF/DMARC."""

    _KEYS = {"domain", "bimi", "tls_rpt", "dkim", "mta_sts", "dmarc_detail", "issues", "score"}

    def _happy_txt(self, dkim_key):
        def fake_txt(host, timeout):
            if host == "_bimi.example.com":
                return ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"], "ok"
            if host == "_smtp._tls.example.com":
                return ["v=TLSRPTv1; rua=mailto:tls@example.com"], "ok"
            if host == "google._domainkey.example.com":
                return [f"v=DKIM1; k=rsa; p={dkim_key}"], "ok"
            if host == "_mta-sts.example.com":
                return ["v=STSv1; id=20260101"], "ok"
            if host == "_dmarc.example.com":
                return ["v=DMARC1; p=reject; sp=reject; pct=100; ruf=mailto:x@example.com"], "ok"
            return [], "absent"

        return fake_txt

    @patch("core.email_auth.httpx.Client")
    @patch("core.email_auth._txt")
    def test_happy_path_reports_documented_keys(self, txt, client_cls):
        key = base64.b64encode(b"\x00" * 256).decode()  # ~2048-bit SubjectPublicKeyInfo
        txt.side_effect = self._happy_txt(key)
        client_cls.return_value = _client(
            get_return=_response(200, "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mx1.example.com")
        )

        result = email_auth.analyze("example.com")

        self.assertEqual(set(result), self._KEYS)
        self.assertTrue(result["bimi"]["present"])
        self.assertEqual(result["bimi"]["logo_url"], "https://example.com/logo.svg")
        self.assertEqual(result["bimi"]["vmc_url"], "https://example.com/vmc.pem")
        self.assertTrue(result["tls_rpt"]["present"])
        self.assertEqual(result["tls_rpt"]["rua"], "mailto:tls@example.com")
        self.assertEqual(result["dkim"]["selectors_found"], ["google"])
        self.assertEqual(result["dkim"]["key_bits"]["google"], 2048)
        self.assertTrue(result["mta_sts"]["dns_present"])
        self.assertTrue(result["mta_sts"]["policy_present"])
        self.assertEqual(result["mta_sts"]["mode"], "enforce")
        self.assertEqual(result["mta_sts"]["max_age"], 604800)
        self.assertEqual(result["mta_sts"]["mx"], ["mx1.example.com"])
        self.assertEqual(result["dmarc_detail"]["sp"], "reject")
        self.assertEqual(result["dmarc_detail"]["pct"], 100)
        self.assertTrue(result["dmarc_detail"]["ruf"])
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["issues"], [])

    @patch("core.email_auth._txt", return_value=([], "failed"))
    def test_lookup_timeout_is_never_reported_as_absence(self, txt):
        result = email_auth.analyze("example.com")

        self.assertIsNone(result["bimi"]["present"])
        self.assertIsNone(result["tls_rpt"]["present"])
        self.assertIsNone(result["mta_sts"]["dns_present"])
        joined = " ".join(result["issues"])
        for claim in (
            "No DMARC record published",
            "No TLS-RPT record",
            "No MTA-STS DNS record",
            "No BIMI record",
        ):
            self.assertNotIn(claim, joined)
        self.assertIn("absence is NOT established", joined)

    @patch("core.email_auth._txt", return_value=([], "absent"))
    def test_genuine_absence_is_reported_as_absence(self, txt):
        """The counterpart to the timeout test: a lookup that completed and
        found no record must be reported as an absence, not left unknown."""
        result = email_auth.analyze("example.com")

        self.assertIs(result["bimi"]["present"], False)
        self.assertIs(result["tls_rpt"]["present"], False)
        self.assertFalse(result["mta_sts"]["dns_present"])
        joined = " ".join(result["issues"])
        self.assertIn("No DMARC record published", joined)
        self.assertIn("No TLS-RPT record", joined)
        self.assertIn("No MTA-STS DNS record", joined)
        self.assertIn("No BIMI record", joined)

    @patch("core.email_auth._txt")
    def test_bimi_and_tls_rpt_completed_nxdomain_is_absent_not_unknown(self, txt):
        """Regression guard for a real bug: `_bimi` and `_tls_rpt` returned
        early for any status other than "ok", so a COMPLETED NXDOMAIN (the
        resolver answered - no such record exists) was reported with
        present=None, the value reserved for "the lookup did not complete".
        `_dmarc` and `_mta_sts` already reported the same input as absent, and
        the visible effect was that the "No BIMI record" / "No TLS-RPT record"
        issues were unreachable for a domain that publishes neither record.

        assertIs(..., False) is deliberate: it distinguishes a real False from
        the None that used to be reported here."""
        txt.side_effect = lambda host, timeout: ([], "absent")
        completed = email_auth.analyze("example.com")
        self.assertIs(completed["bimi"]["present"], False)
        self.assertIs(completed["tls_rpt"]["present"], False)
        joined = " ".join(completed["issues"])
        self.assertIn("No BIMI record", joined)
        self.assertIn("No TLS-RPT record", joined)

        # The other half of the rule must not regress: a lookup that did not
        # complete stays unknown and claims no absence.
        txt.side_effect = lambda host, timeout: ([], "failed")
        failed = email_auth.analyze("example.com")
        self.assertIsNone(failed["bimi"]["present"])
        self.assertIsNone(failed["tls_rpt"]["present"])
        failed_issues = " ".join(failed["issues"])
        self.assertIn("BIMI lookup did not complete", failed_issues)
        self.assertIn("TLS-RPT lookup did not complete", failed_issues)
        self.assertNotIn("No BIMI record", failed_issues)
        self.assertNotIn("No TLS-RPT record", failed_issues)

    @patch("core.email_auth._txt")
    def test_bimi_urls_are_stripped_of_tag_separators(self, txt):
        """Regression guard: the BIMI record is semicolon-separated, so a value
        followed by another tag was captured together with the ';' separator
        and handed back as part of the URL. Both tag orders must be clean."""
        records = (
            "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
            "v=BIMI1; a=https://example.com/vmc.pem; l=https://example.com/logo.svg",
        )
        for record in records:
            txt.side_effect = lambda host, timeout, rec=record: (
                ([rec], "ok") if host == "_bimi.example.com" else ([], "absent")
            )
            result = email_auth.analyze("example.com")

            self.assertEqual(result["bimi"]["logo_url"], "https://example.com/logo.svg")
            self.assertEqual(result["bimi"]["vmc_url"], "https://example.com/vmc.pem")
            for value in (result["bimi"]["logo_url"], result["bimi"]["vmc_url"]):
                self.assertNotIn(";", value)

    @patch("core.email_auth.httpx.Client")
    @patch("core.email_auth._txt")
    def test_unreachable_policy_file_is_unknown_not_absent(self, txt, client_cls):
        def fake_txt(host, timeout):
            if host == "_mta-sts.example.com":
                return ["v=STSv1; id=20260101"], "ok"
            return [], "absent"

        txt.side_effect = fake_txt
        client_cls.return_value = _client(get_side_effect=httpx.ConnectError("boom"))

        result = email_auth.analyze("example.com")

        self.assertTrue(result["mta_sts"]["dns_present"])
        self.assertIsNone(result["mta_sts"]["policy_present"])
        joined = " ".join(result["issues"])
        self.assertIn("policy file could not be retrieved", joined)
        self.assertNotIn("no policy file was served", joined)

    @patch("core.email_auth._txt")
    def test_weak_and_revoked_dkim_keys_are_flagged(self, txt):
        weak = base64.b64encode(b"\x00" * 64).decode()  # ~512-bit key

        def fake_txt(host, timeout):
            if host == "default._domainkey.example.com":
                return [f"v=DKIM1; k=rsa; p={weak}"], "ok"
            if host == "test._domainkey.example.com":
                return ["v=DKIM1; k=rsa; p="], "ok"
            return [], "absent"

        txt.side_effect = fake_txt
        result = email_auth.analyze("example.com")

        self.assertEqual(result["dkim"]["key_bits"]["default"], 512)
        self.assertEqual(result["dkim"]["key_bits"]["test"], 0)
        joined = " ".join(result["issues"])
        self.assertIn("shorter than 1024 bits", joined)
        self.assertIn("revoked key", joined)

    @patch("core.email_auth._txt", return_value=([], "absent"))
    def test_malformed_input_never_raises(self, txt):
        for value in ("", None, "..", "not a domain!!"):
            result = email_auth.analyze(value)
            self.assertEqual(set(result), self._KEYS)


class AsnIntelTests(unittest.TestCase):
    """core.asn_intel - failed lookup is not an unannounced address."""

    _KEYS = {
        "ip", "asn", "prefix", "country", "registry", "allocated", "as_name",
        "source", "is_private", "lookup_failed", "notes", "errors",
    }

    @patch("core.asn_intel._pyasn_crosscheck", return_value=(None, []))
    @patch("core.asn_intel._txt")
    def test_happy_path_reports_documented_keys(self, txt, crosscheck):
        def fake_txt(hostname, timeout):
            if hostname == "1.1.1.1.origin.asn.cymru.com":
                return ["13335 | 1.1.1.0/24 | US | arin | 2011-08-11"], True
            if hostname == "AS13335.asn.cymru.com":
                return ["13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"], True
            return [], True

        txt.side_effect = fake_txt
        result = asn_intel.analyze("1.1.1.1")

        self.assertEqual(set(result), self._KEYS)
        self.assertEqual(result["asn"], 13335)
        self.assertEqual(result["prefix"], "1.1.1.0/24")
        self.assertEqual(result["country"], "US")
        self.assertEqual(result["registry"], "arin")
        self.assertEqual(result["allocated"], "2011-08-11")
        self.assertEqual(result["as_name"], "CLOUDFLARENET, US")
        self.assertEqual(result["source"], "team-cymru")
        self.assertFalse(result["is_private"])
        self.assertFalse(result["lookup_failed"])
        self.assertEqual(result["errors"], [])

    @patch("core.asn_intel._pyasn_crosscheck", return_value=(None, []))
    @patch("core.asn_intel._txt", return_value=([], False))
    def test_failed_lookup_is_not_an_unannounced_address(self, txt, crosscheck):
        # 8.8.8.8, not a TEST-NET address: Python's ipaddress flags 203.0.113.0/24
        # as non-public and asn_intel short-circuits those before any lookup.
        result = asn_intel.analyze("8.8.8.8")

        self.assertTrue(result["lookup_failed"])
        self.assertIsNone(result["asn"])
        self.assertTrue(result["errors"])
        self.assertFalse(any("not announced" in note for note in result["notes"]))

    @patch("core.asn_intel._pyasn_crosscheck", return_value=(None, []))
    @patch("core.asn_intel._txt", return_value=([], True))
    def test_completed_lookup_with_no_answer_is_reported_as_absence(self, txt, crosscheck):
        result = asn_intel.analyze("8.8.8.8")

        self.assertFalse(result["lookup_failed"])
        self.assertIsNone(result["asn"])
        self.assertEqual(result["errors"], [])
        self.assertTrue(any("returned no origin record" in note for note in result["notes"]))

    @patch("core.asn_intel._txt", return_value=([], True))
    def test_private_and_malformed_addresses_never_raise(self, txt):
        malformed = asn_intel.analyze("not-an-ip")
        self.assertTrue(malformed["lookup_failed"])
        self.assertTrue(malformed["errors"])
        self.assertIsNone(malformed["asn"])

        empty = asn_intel.analyze("")
        self.assertTrue(empty["lookup_failed"])

        private = asn_intel.analyze("10.0.0.1")
        self.assertTrue(private["is_private"])
        self.assertFalse(private["lookup_failed"])
        self.assertEqual(private["errors"], [])
        self.assertTrue(private["notes"])
        # A private address is never queried at all.
        txt.assert_not_called()

    @patch("core.asn_intel._pyasn_crosscheck", return_value=(None, []))
    @patch("core.asn_intel._txt", return_value=([], True))
    def test_ipv6_uses_the_nibble_reversed_origin_zone(self, txt, crosscheck):
        asn_intel.analyze("2606:4700::1111")

        queried = txt.call_args[0][0]
        self.assertTrue(queried.endswith(".origin6.asn.cymru.com"))
        self.assertTrue(queried.startswith("1.1.1.1"))


class ReputationTests(unittest.TestCase):
    """core.reputation - 404 is data, a refusal is not a listing."""

    _KEYS = {"ip", "shodan_internetdb", "dnsbl", "issues", "lookup_failed", "errors"}
    _SHODAN_KEYS = {"available", "ports", "hostnames", "cpes", "vulns", "tags", "error"}
    _DNSBL_KEYS = {"listed", "checked", "refused", "note"}
    _IP_ZONES = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "dnsbl.sorbs.net"]

    @patch("core.reputation._pydnsbl_extra")
    @patch("core.reputation._a_records", return_value=([], True))
    @patch("core.reputation._http_get_json", return_value=(404, None, None))
    def test_http_404_from_shodan_is_a_normal_no_data_answer(self, http, a_records, pydnsbl):
        result = reputation.analyze("203.0.113.5")

        self.assertEqual(set(result), self._KEYS)
        self.assertEqual(set(result["shodan_internetdb"]), self._SHODAN_KEYS)
        self.assertEqual(set(result["dnsbl"]), self._DNSBL_KEYS)
        self.assertFalse(result["shodan_internetdb"]["available"])
        self.assertIsNone(result["shodan_internetdb"]["error"])
        self.assertEqual(result["errors"], [])
        self.assertFalse(result["lookup_failed"])
        self.assertEqual(sorted(result["dnsbl"]["checked"]), sorted(self._IP_ZONES))

    @patch("core.reputation._pydnsbl_extra")
    @patch("core.reputation._a_records")
    @patch("core.reputation._http_get_json", return_value=(404, None, None))
    def test_spamhaus_refusal_lands_in_refused_not_listed(self, http, a_records, pydnsbl):
        def fake_a(name, timeout):
            if name.endswith("zen.spamhaus.org"):
                return ["127.255.255.254"], True
            return [], True

        a_records.side_effect = fake_a
        result = reputation.analyze("203.0.113.5")

        self.assertEqual(result["dnsbl"]["refused"], ["zen.spamhaus.org"])
        self.assertEqual(result["dnsbl"]["listed"], [])
        self.assertNotIn("zen.spamhaus.org", result["dnsbl"]["checked"])
        self.assertFalse(any("zen.spamhaus.org" in issue for issue in result["issues"]))

    @patch("core.reputation._pydnsbl_extra")
    @patch("core.reputation._a_records")
    @patch("core.reputation._http_get_json", return_value=(404, None, None))
    def test_genuine_listing_is_reported_with_its_sublist(self, http, a_records, pydnsbl):
        def fake_a(name, timeout):
            if name.endswith("zen.spamhaus.org"):
                return ["127.0.0.4"], True
            return [], True

        a_records.side_effect = fake_a
        result = reputation.analyze("203.0.113.5")

        self.assertEqual(len(result["dnsbl"]["listed"]), 1)
        entry = result["dnsbl"]["listed"][0]
        self.assertEqual(entry["zone"], "zen.spamhaus.org")
        self.assertEqual(entry["response"], "127.0.0.4")
        self.assertIn("XBL", entry["reason"])
        self.assertIn("zen.spamhaus.org", result["dnsbl"]["checked"])
        self.assertTrue(any("zen.spamhaus.org" in issue for issue in result["issues"]))

    @patch("core.reputation._pydnsbl_extra")
    @patch("core.reputation._a_records", return_value=([], True))
    @patch("core.reputation._http_get_json")
    def test_shodan_payload_vulns_and_tags_become_issues(self, http, a_records, pydnsbl):
        http.return_value = (
            200,
            {"ports": [80, 443], "hostnames": ["a.example"], "cpes": [], "vulns": ["CVE-2021-1234"], "tags": ["tor"]},
            None,
        )
        result = reputation.analyze("203.0.113.5")

        self.assertTrue(result["shodan_internetdb"]["available"])
        self.assertEqual(result["shodan_internetdb"]["ports"], [80, 443])
        self.assertEqual(result["shodan_internetdb"]["hostnames"], ["a.example"])
        joined = " ".join(result["issues"])
        self.assertIn("CVE-2021-1234", joined)
        self.assertIn("tor", joined)

    @patch("core.reputation._pydnsbl_extra")
    @patch("core.reputation._a_records", return_value=([], False))
    @patch("core.reputation._http_get_json", return_value=(None, None, "ConnectError: boom"))
    def test_transport_failures_never_raise_and_are_not_clean(self, http, a_records, pydnsbl):
        result = reputation.analyze("203.0.113.5")

        self.assertTrue(result["errors"])
        self.assertTrue(result["lookup_failed"])
        self.assertIsNotNone(result["shodan_internetdb"]["error"])

    @patch("core.reputation._pydnsbl_extra")
    @patch("core.reputation._a_records", return_value=([], True))
    @patch("core.reputation._http_get_json", return_value=(404, None, None))
    def test_malformed_ip_and_domain_never_raise(self, http, a_records, pydnsbl):
        malformed = reputation.analyze("not-an-ip")
        self.assertTrue(malformed["lookup_failed"])
        self.assertTrue(malformed["errors"])
        http.assert_not_called()

        empty = reputation.analyze("")
        self.assertTrue(empty["lookup_failed"])

        bad_domain = reputation.analyze("203.0.113.5", domain="not a domain")
        self.assertTrue(any("not a usable domain name" in error for error in bad_domain["errors"]))

        with_domain = reputation.analyze("203.0.113.5", domain="example.com")
        self.assertIn("dbl.spamhaus.org", with_domain["dnsbl"]["checked"])
        self.assertIn("multi.surbl.org", with_domain["dnsbl"]["checked"])


class CloudBucketsTests(unittest.TestCase):
    """core.cloud_buckets - a 403 is an existing private bucket, never an exposure."""

    _KEYS = {"domain", "candidates", "found", "issues", "errors", "unverified", "checked"}
    _ENTRY_KEYS = {"provider", "name", "url", "status", "accessible", "listable", "detail"}
    _LISTING = "<ListBucketResult><Contents><Key>a.txt</Key></Contents></ListBucketResult>"

    @patch("core.cloud_buckets.httpx.Client")
    def test_publicly_listable_bucket_is_reported(self, client_cls):
        def get(url, headers=None, **kwargs):
            if url == "https://example.s3.amazonaws.com/":
                return _response(200, self._LISTING)
            return _response(404, "NoSuchBucket")

        client_cls.return_value = _client(get_side_effect=get)
        result = cloud_buckets.enumerate_buckets("example.com", max_candidates=1)

        self.assertEqual(set(result), self._KEYS)
        self.assertEqual(result["candidates"], ["example"])
        self.assertEqual(result["checked"], 3)
        self.assertEqual(len(result["found"]), 1)
        entry = result["found"][0]
        self.assertEqual(set(entry), self._ENTRY_KEYS)
        self.assertEqual(entry["provider"], "aws")
        self.assertTrue(entry["listable"])
        self.assertTrue(entry["accessible"])
        self.assertTrue(any("publicly listable" in issue for issue in result["issues"]))

    @patch("core.cloud_buckets.httpx.Client")
    def test_403_is_existing_but_not_listable_and_never_an_exposure(self, client_cls):
        body = "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
        client_cls.return_value = _client(get_return=_response(403, body))

        result = cloud_buckets.enumerate_buckets("example.com", max_candidates=1)

        self.assertEqual(result["checked"], 3)
        self.assertEqual(len(result["found"]), 3)
        for entry in result["found"]:
            self.assertFalse(entry["listable"])
            self.assertFalse(entry["accessible"])
            self.assertIn("anonymous listing denied", entry["detail"])
            self.assertIn("AccessDenied", entry["detail"])
        self.assertFalse(any("publicly listable" in issue for issue in result["issues"]))
        self.assertTrue(all("denies anonymous listing" in issue for issue in result["issues"]))

    @patch("core.cloud_buckets.httpx.Client")
    def test_200_without_listing_markers_is_not_treated_as_listable(self, client_cls):
        client_cls.return_value = _client(get_return=_response(200, "<html><body>Welcome</body></html>"))

        result = cloud_buckets.enumerate_buckets("example.com", max_candidates=1)

        self.assertEqual(len(result["found"]), 3)
        for entry in result["found"]:
            self.assertFalse(entry["listable"])
            self.assertIn("does not match the provider listing format", entry["detail"])

    @patch("core.cloud_buckets.httpx.Client")
    def test_max_candidates_caps_the_number_of_probes(self, client_cls):
        client_cls.return_value = _client(get_return=_response(404, "NoSuchBucket"))

        result = cloud_buckets.enumerate_buckets("example.com", max_candidates=2)

        self.assertEqual(result["candidates"], ["example", "example-backup"])
        self.assertEqual(result["checked"], 6)
        self.assertLessEqual(result["checked"], 2 * 3)
        self.assertEqual(result["found"], [])

    @patch("core.cloud_buckets.httpx.Client")
    def test_connect_timeout_is_not_reported_as_absent(self, client_cls):
        """Regression guard: a timeout is a transient network condition, so it
        must reach no verdict - never 'the bucket name is not in use'."""
        client_cls.return_value = _client(get_side_effect=httpx.ConnectTimeout("timed out"))

        result = cloud_buckets.enumerate_buckets("example.com", max_candidates=1)

        self.assertEqual(result["found"], [])
        self.assertEqual(len(result["unverified"]), 3)
        for record in result["unverified"]:
            self.assertIn("ConnectTimeout", record["reason"])
        self.assertTrue(result["errors"])

    @patch("core.cloud_buckets.httpx.Client")
    def test_unexpected_status_is_not_reported_as_an_existing_bucket(self, client_cls):
        """Regression guard: a 503 (or a WAF block page) is the provider failing
        to answer about the name, not evidence that the bucket exists."""
        client_cls.return_value = _client(get_return=_response(503, "<html>Service Unavailable</html>"))

        result = cloud_buckets.enumerate_buckets("example.com", max_candidates=1)

        self.assertEqual(result["found"], [])
        self.assertEqual(len(result["unverified"]), 3)
        for record in result["unverified"]:
            self.assertEqual(record["status"], 503)
            self.assertIn("existence not established", record["reason"])
        self.assertFalse(any("exists" in issue for issue in result["issues"]))

    @patch("core.cloud_buckets.httpx.Client")
    def test_only_a_clean_404_or_a_name_resolution_failure_means_absent(self, client_cls):
        """The two definitive absences. Neither is a bucket, and neither is an
        unverified probe."""
        client_cls.return_value = _client(get_return=_response(404, "NoSuchBucket"))
        clean_404 = cloud_buckets.enumerate_buckets("example.com", max_candidates=1)
        self.assertEqual(clean_404["found"], [])
        self.assertEqual(clean_404["unverified"], [])
        self.assertEqual(clean_404["errors"], [])

        client_cls.return_value = _client(
            get_side_effect=httpx.ConnectError("[Errno -2] Name or service not known")
        )
        dns_failure = cloud_buckets.enumerate_buckets("example.com", max_candidates=1)
        self.assertEqual(dns_failure["found"], [])
        self.assertEqual(dns_failure["unverified"], [])
        self.assertEqual(dns_failure["errors"], [])

    @patch("core.cloud_buckets.httpx.Client")
    def test_generic_connect_error_is_unknown_but_a_read_timeout_is_recorded(self, client_cls):
        client_cls.return_value = _client(get_side_effect=httpx.ConnectError("connection refused"))
        refused = cloud_buckets.enumerate_buckets("example.com", max_candidates=1)
        self.assertEqual(refused["found"], [])
        self.assertEqual(len(refused["unverified"]), 3)
        self.assertTrue(refused["errors"])

        client_cls.return_value = _client(get_side_effect=httpx.ReadTimeout("slow"))
        failed = cloud_buckets.enumerate_buckets("example.com", max_candidates=1)
        self.assertEqual(failed["found"], [])
        self.assertEqual(len(failed["unverified"]), 3)
        self.assertTrue(failed["errors"])

    @patch("core.cloud_buckets.httpx.Client")
    def test_a_bare_400_is_not_existence_but_a_provider_error_document_is(self, client_cls):
        """Only a 400 carrying the provider's own <Code> document counts as an
        existing-but-denied name; a bare 400 is no verdict."""
        client_cls.return_value = _client(get_return=_response(400, "<html>Bad Request</html>"))
        bare = cloud_buckets.enumerate_buckets("example.com", max_candidates=1)
        self.assertEqual(bare["found"], [])
        self.assertEqual(len(bare["unverified"]), 3)

        azure = "<Error><Code>InvalidUri</Code><Message>...</Message></Error>"
        client_cls.return_value = _client(get_return=_response(400, azure))
        documented = cloud_buckets.enumerate_buckets("example.com", max_candidates=1)
        self.assertEqual(len(documented["found"]), 3)
        for entry in documented["found"]:
            self.assertFalse(entry["listable"])
            self.assertIn("InvalidUri", entry["detail"])

    @patch("core.cloud_buckets.httpx.Client")
    def test_malformed_domain_never_raises(self, client_cls):
        client_cls.return_value = _client(get_return=_response(404, "NoSuchBucket"))

        for value in ("", None, "!!!", "https://"):
            result = cloud_buckets.enumerate_buckets(value, max_candidates=2)
            self.assertEqual(set(result), self._KEYS)
            self.assertEqual(result["found"], [])


class ExposureTests(unittest.TestCase):
    """core.exposure - a catch-all 200 must not become a finding."""

    _KEYS = {
        "base_url", "findings", "candidates", "directory_listing", "security_txt",
        "crossdomain", "source_maps", "checked", "errors",
    }

    @patch("core.exposure.httpx.Client")
    def test_catchall_200_html_produces_no_env_or_git_findings(self, client_cls):
        """The content-verification guard: a router that answers 200 with an HTML
        shell for every path must not be reported as an exposure."""
        shell = "<!DOCTYPE html><html><body><h1>Not Found</h1></body></html>"
        client_cls.return_value = _client(get_side_effect=lambda url, headers=None, **kw: _response(200, shell))

        result = exposure.analyze("https://target.example", fetch_source_maps=False)

        self.assertEqual(set(result), self._KEYS)
        reported = [f for f in result["findings"] if f["path"] in ("/.env", "/.git/HEAD")]
        self.assertEqual(reported, [])
        candidate_paths = {c["path"] for c in result["candidates"]}
        self.assertIn("/.env", candidate_paths)
        self.assertIn("/.git/HEAD", candidate_paths)
        self.assertFalse(result["directory_listing"])

    @patch("core.exposure.httpx.Client")
    def test_content_verified_artefacts_are_findings(self, client_cls):
        def get(url, headers=None, **kwargs):
            path = urlsplit(url).path
            if path == "/.git/HEAD":
                return _response(200, "ref: refs/heads/main\n")
            if path == "/.env":
                return _response(200, "DB_PASSWORD=hunter2\nAPI_KEY=abcd1234\n")
            return _response(404, "Not Found")

        client_cls.return_value = _client(get_side_effect=get)
        result = exposure.analyze("https://target.example", fetch_source_maps=False)

        by_path = {f["path"]: f for f in result["findings"]}
        self.assertEqual(by_path["/.git/HEAD"]["kind"], "git_disclosure")
        self.assertEqual(by_path["/.git/HEAD"]["severity"], "high")
        self.assertEqual(by_path["/.env"]["kind"], "credentials")
        self.assertEqual(by_path["/.env"]["severity"], "critical")
        self.assertFalse(any(c["path"] in ("/.env", "/.git/HEAD") for c in result["candidates"]))

    @patch("core.exposure.httpx.Client")
    def test_expired_security_txt_is_a_finding(self, client_cls):
        def get(url, headers=None, **kwargs):
            path = urlsplit(url).path
            if path in ("/.well-known/security.txt", "/security.txt"):
                return _response(200, "Contact: mailto:sec@example.com\nExpires: 2020-01-01T00:00:00Z\n")
            return _response(404, "Not Found")

        client_cls.return_value = _client(get_side_effect=get)
        result = exposure.analyze("https://target.example", fetch_source_maps=False)

        self.assertTrue(result["security_txt"]["present"])
        self.assertTrue(result["security_txt"]["expired"])
        self.assertTrue(
            any(
                f["kind"] == "security_txt" and "Expires date is in the past" in f["detail"]
                for f in result["findings"]
            )
        )

    @patch("core.exposure.httpx.Client")
    def test_crossdomain_wildcard_is_a_finding(self, client_cls):
        policy = '<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>'

        def get(url, headers=None, **kwargs):
            if urlsplit(url).path == "/crossdomain.xml":
                return _response(200, policy)
            return _response(404, "Not Found")

        client_cls.return_value = _client(get_side_effect=get)
        result = exposure.analyze("https://target.example", fetch_source_maps=False)

        self.assertTrue(result["crossdomain"]["present"])
        self.assertTrue(result["crossdomain"]["wildcard"])
        self.assertTrue(
            any(f["kind"] == "crossdomain_policy" and f["severity"] == "medium" for f in result["findings"])
        )

    @patch("core.exposure.httpx.Client")
    def test_published_source_map_is_a_finding(self, client_cls):
        def get(url, headers=None, **kwargs):
            path = urlsplit(url).path
            if path == "/":
                return _response(200, '<html><head><script src="/app.js"></script></head></html>')
            if path == "/app.js.map":
                return _response(200, json.dumps({"version": 3, "sources": ["a.ts", "b.ts"]}))
            return _response(404, "Not Found")

        client_cls.return_value = _client(get_side_effect=get)
        result = exposure.analyze("https://target.example")

        self.assertEqual(len(result["source_maps"]), 1)
        self.assertEqual(result["source_maps"][0]["sources"], 2)
        self.assertTrue(any(f["kind"] == "source_map" for f in result["findings"]))

    @patch("core.exposure.httpx.Client")
    def test_transport_failure_never_raises_and_claims_no_absence(self, client_cls):
        """Both security.txt locations failing at the transport layer means the
        absence is NOT established, so no 'no security.txt published' finding."""
        client_cls.return_value = _client(get_side_effect=httpx.ConnectError("boom"))

        result = exposure.analyze("https://target.example", fetch_source_maps=False)

        self.assertTrue(result["errors"])
        self.assertEqual(result["findings"], [])
        self.assertFalse(any(f["kind"] == "security_txt" for f in result["findings"]))
        self.assertEqual(result["checked"], 23)

    @patch("core.exposure.httpx.Client")
    def test_malformed_base_url_never_raises(self, client_cls):
        client_cls.return_value = _client(get_side_effect=httpx.ConnectError("boom"))

        for value in ("", None, "not a url"):
            result = exposure.analyze(value, max_paths=2, fetch_source_maps=False)
            self.assertEqual(set(result), self._KEYS)


class HttpProtocolTests(unittest.TestCase):
    """core.http_protocol - pure header analysis; absent alt-svc is unknown."""

    _KEYS = {
        "http_version", "http2", "http3", "alt_svc", "compression", "server_timing",
        "tls_protocol", "issues", "errors",
    }

    def test_alt_svc_advertising_h3_sets_http3(self):
        result = http_protocol.analyze({"alt-svc": 'h3=":443"; ma=86400, h2=":443"'})

        self.assertEqual(set(result), self._KEYS)
        self.assertTrue(result["http3"])
        self.assertTrue(result["http2"])
        self.assertIn("h3", result["alt_svc"])

    def test_absent_alt_svc_yields_none_never_false(self):
        result = http_protocol.analyze({})

        self.assertIsNone(result["http3"])
        self.assertIsNone(result["http2"])
        self.assertIsNone(result["alt_svc"])

    def test_alt_svc_clear_is_a_determination_not_an_absence(self):
        result = http_protocol.analyze({"Alt-Svc": "clear"})

        self.assertFalse(result["http3"])
        self.assertFalse(result["http2"])
        self.assertEqual(result["alt_svc"], "clear")

    def test_compression_and_server_timing_are_parsed(self):
        result = http_protocol.analyze({"Content-Encoding": "gzip, br", "Server-Timing": "db;dur=53"})

        self.assertEqual(result["compression"], ["gzip", "br"])
        self.assertTrue(result["server_timing"])

    def test_malformed_headers_never_raise(self):
        for value in ({}, None, {"alt-svc": ""}):
            result = http_protocol.analyze(value)
            self.assertEqual(set(result), self._KEYS)

    @patch("core.http_protocol.httpx.Client")
    def test_live_request_negotiating_http2_promotes_http2(self, client_cls):
        client_cls.return_value = _client(
            get_return=_response(200, "body", headers={"content-encoding": "gzip"}, http_version="HTTP/2")
        )

        result = http_protocol.analyze({}, url="https://target.example")

        self.assertEqual(result["http_version"], "HTTP/2")
        self.assertTrue(result["http2"])
        self.assertIn("gzip", result["compression"])
        self.assertEqual(result["errors"], [])

    @patch("core.http_protocol.httpx.Client")
    def test_live_request_failure_is_recorded_not_raised(self, client_cls):
        client_cls.return_value = _client(get_side_effect=httpx.ConnectError("boom"))

        result = http_protocol.analyze({}, url="https://target.example")

        self.assertTrue(result["errors"])
        self.assertIsNone(result["http_version"])
        self.assertEqual(set(result), self._KEYS)


class VhostTests(unittest.TestCase):
    """core.vhost - an identical 200 body is a catch-all, not a vhost."""

    _KEYS = {"ip", "hostname", "scheme", "baseline", "candidates_checked", "found", "issues", "errors"}

    @patch("core.vhost.httpx.Client")
    def test_identical_200_body_is_not_reported_as_a_vhost(self, client_cls):
        page = "<html><title>Welcome</title><body>hello world, this is the default site</body></html>"
        client_cls.return_value = _client(
            get_side_effect=lambda url, headers=None, timeout=None, **kw: _response(200, page)
        )

        result = vhost.discover("203.0.113.9", "example.com", max_candidates=3)

        self.assertEqual(set(result), self._KEYS)
        self.assertEqual(result["found"], [])
        self.assertEqual(result["candidates_checked"], 6)
        self.assertTrue(any("catch-all" in issue for issue in result["issues"]))

    @patch("core.vhost.httpx.Client")
    def test_a_meaningfully_different_response_is_reported(self, client_cls):
        default = "<html><title>Welcome</title><body>hello world default site</body></html>"
        other = "<html><title>Admin Console</title><body>" + ("x" * 500) + "</body></html>"

        def get(url, headers=None, timeout=None, **kwargs):
            if (headers or {}).get("Host") == "admin.example.com":
                return _response(200, other)
            return _response(200, default)

        client_cls.return_value = _client(get_side_effect=get)
        result = vhost.discover("203.0.113.9", "example.com", max_candidates=1)

        self.assertEqual(len(result["found"]), 1)
        self.assertEqual(result["found"][0]["host"], "admin.example.com")
        self.assertEqual(result["found"][0]["title"], "Admin Console")
        self.assertTrue(result["found"][0]["distinct"])
        self.assertLessEqual(result["candidates_checked"], 1 * 2)

    @patch("core.vhost.httpx.Client")
    def test_without_a_baseline_nothing_is_reported_as_found(self, client_cls):
        """No baseline means no comparison is possible, so a differing-looking
        candidate must not be promoted to a finding."""
        other = "<html><title>Admin Console</title><body>" + ("x" * 500) + "</body></html>"

        def get(url, headers=None, timeout=None, **kwargs):
            if (headers or {}).get("Host") == "203.0.113.9":
                raise httpx.ConnectError("baseline unreachable")
            return _response(200, other)

        client_cls.return_value = _client(get_side_effect=get)
        result = vhost.discover("203.0.113.9", "example.com", max_candidates=1)

        self.assertEqual(result["found"], [])
        self.assertTrue(result["errors"])
        self.assertTrue(any("No usable baseline" in issue for issue in result["issues"]))

    @patch("core.vhost.httpx.Client")
    def test_https_only_target_is_reached_by_retrying_the_baseline(self, client_cls):
        """Regression guard: with a hardcoded http baseline an HTTPS-only host
        produced nothing. The baseline is retried once over https and whichever
        scheme answered is used for every candidate."""
        default = "<html><title>Welcome</title><body>hello world default site</body></html>"
        admin = "<html><title>Admin Console</title><body>" + ("x" * 500) + "</body></html>"

        def get(url, headers=None, timeout=None, **kwargs):
            if url.startswith("http://"):
                raise httpx.ConnectError("connection refused")
            if (headers or {}).get("Host") == "admin.example.com":
                return _response(200, admin)
            return _response(200, default)

        client_cls.return_value = _client(get_side_effect=get)
        result = vhost.discover("203.0.113.9", "example.com", max_candidates=1)

        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["baseline"]["status"], 200)
        self.assertEqual([entry["host"] for entry in result["found"]], ["admin.example.com"])
        self.assertEqual(result["candidates_checked"], 2)

    @patch("core.vhost.httpx.Client")
    def test_scheme_is_detected_once_and_not_per_candidate(self, client_cls):
        """The fallback stays bounded: the baseline settles the scheme, so the
        candidate probes are never doubled."""
        calls = []
        page = "<html><title>Welcome</title><body>hello world default site</body></html>"

        def get(url, headers=None, timeout=None, **kwargs):
            calls.append(url)
            if url.startswith("http://"):
                raise httpx.ConnectError("connection refused")
            return _response(200, page)

        client_cls.return_value = _client(get_side_effect=get)
        result = vhost.discover("203.0.113.9", "example.com", max_candidates=2)

        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["candidates_checked"], 4)
        # 1 failed http baseline + 1 https baseline + 4 candidate requests
        self.assertEqual(len(calls), 6)
        self.assertTrue(all(url.startswith("https://") for url in calls[1:]))

    @patch("core.vhost.httpx.Client")
    def test_when_no_scheme_answers_the_issue_names_what_was_tried(self, client_cls):
        client_cls.return_value = _client(get_side_effect=httpx.ConnectError("boom"))

        result = vhost.discover("203.0.113.9", "example.com", max_candidates=1)

        self.assertEqual(result["found"], [])
        self.assertTrue(any("No usable baseline" in issue and "http" in issue and "https" in issue
                            for issue in result["issues"]))

    @patch("core.vhost.httpx.Client")
    def test_malformed_input_never_raises(self, client_cls):
        client_cls.return_value = _client(get_side_effect=httpx.ConnectError("boom"))

        for ip, hostname in (("", ""), (None, None), ("not-an-ip", "not a host")):
            result = vhost.discover(ip, hostname, max_candidates=1)
            self.assertEqual(set(result), self._KEYS)
            self.assertEqual(result["found"], [])


class SubdomainBruteTests(unittest.TestCase):
    """core.subdomain_brute - wildcard answers must be filtered out."""

    _KEYS = {
        "domain", "words_checked", "found", "wildcard", "permutations_checked",
        "candidates_attempted", "issues", "errors",
    }
    _WILDCARD_IP = "198.51.100.7"

    @patch("core.subdomain_brute._lookup", return_value={"ips": [_WILDCARD_IP], "cnames": []})
    def test_wildcard_answers_are_filtered_out(self, lookup):
        """The module's whole reason for existing: with a wildcard every word
        'resolves', and reporting them all would be pure noise."""
        result = subdomain_brute.bruteforce("example.com", wordlist=["www", "api", "admin"], timeout=1)

        self.assertEqual(set(result), self._KEYS)
        self.assertTrue(result["wildcard"]["detected"])
        self.assertEqual(result["wildcard"]["ips"], [self._WILDCARD_IP])
        self.assertEqual(result["words_checked"], 3)
        self.assertEqual(result["found"], [])
        self.assertTrue(any("wildcard DNS detected" in issue for issue in result["issues"]))

    @patch("core.subdomain_brute._lookup")
    def test_a_real_host_survives_wildcard_filtering(self, lookup):
        """Filtering is subset-based: a candidate on a different address is a
        real hit even while its neighbours echo the wildcard."""
        def fake_lookup(host, timeout):
            if host.startswith("inoue-wc-"):
                return {"ips": [self._WILDCARD_IP], "cnames": []}
            if host == "www.example.com":
                return {"ips": ["203.0.113.50"], "cnames": []}
            return {"ips": [self._WILDCARD_IP], "cnames": []}

        lookup.side_effect = fake_lookup
        result = subdomain_brute.bruteforce(
            "example.com", wordlist=["www", "api"], timeout=1, permutations=False
        )

        self.assertEqual([entry["host"] for entry in result["found"]], ["www.example.com"])
        self.assertEqual(result["found"][0]["ips"], ["203.0.113.50"])

    @patch("core.subdomain_brute._lookup")
    def test_clean_zone_reports_the_hits(self, lookup):
        def fake_lookup(host, timeout):
            if host == "www.example.com":
                return {"ips": ["203.0.113.50"], "cnames": []}
            return None

        lookup.side_effect = fake_lookup
        result = subdomain_brute.bruteforce(
            "example.com", wordlist=["www", "api"], timeout=1, permutations=False
        )

        self.assertFalse(result["wildcard"]["detected"])
        self.assertEqual(result["words_checked"], 2)
        self.assertEqual([entry["host"] for entry in result["found"]], ["www.example.com"])
        self.assertEqual(result["errors"], [])

    @patch("core.subdomain_brute._lookup")
    def test_max_candidates_caps_wordlist_and_permutations(self, lookup):
        def fake_lookup(host, timeout):
            if host == "www.example.com":
                return {"ips": ["203.0.113.50"], "cnames": []}
            return None

        lookup.side_effect = fake_lookup
        capped_words = subdomain_brute.bruteforce(
            "example.com", wordlist=["w%d" % i for i in range(10)], timeout=1,
            max_candidates=5, permutations=False,
        )
        self.assertEqual(capped_words["words_checked"], 5)
        self.assertLessEqual(capped_words["candidates_attempted"], 5)
        self.assertTrue(any("candidate cap reached" in issue for issue in capped_words["issues"]))

        with_perms = subdomain_brute.bruteforce(
            "example.com", wordlist=["www"], timeout=1, max_candidates=5, permutations=True
        )
        self.assertEqual(with_perms["permutations_checked"], 4)
        self.assertLessEqual(with_perms["candidates_attempted"], 5)

    @patch("core.subdomain_brute._lookup", side_effect=RuntimeError("resolver blew up"))
    def test_resolver_failure_is_never_reported_as_a_found_host(self, lookup):
        result = subdomain_brute.bruteforce(
            "example.com", wordlist=["www", "api"], timeout=1, permutations=False
        )

        self.assertEqual(result["found"], [])
        self.assertTrue(result["errors"])

    @patch("core.subdomain_brute._lookup", return_value=None)
    def test_domain_is_normalised(self, lookup):
        result = subdomain_brute.bruteforce(
            "https://Example.COM:8443/path?q=1", wordlist=["www"], timeout=1, permutations=False
        )

        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(set(result), self._KEYS)

    @patch("core.subdomain_brute._lookup", return_value=None)
    def test_empty_domain_and_zero_cap_do_no_lookups(self, lookup):
        empty = subdomain_brute.bruteforce("", wordlist=["www"])
        self.assertEqual(empty["found"], [])
        self.assertTrue(any("empty or invalid domain" in issue for issue in empty["issues"]))

        zero = subdomain_brute.bruteforce("example.com", max_candidates=0)
        self.assertEqual(zero["found"], [])
        self.assertTrue(any("max_candidates is 0" in issue for issue in zero["issues"]))
        lookup.assert_not_called()


class SriTests(unittest.TestCase):
    """core.sri - pure and offline; third-party is what matters."""

    _KEYS = {
        "scripts_total", "scripts_external", "scripts_missing_integrity",
        "stylesheets_total", "stylesheets_external", "stylesheets_missing_integrity",
        "crossorigin_missing", "findings", "score", "issues", "errors",
    }

    def test_third_party_script_without_integrity_is_flagged(self):
        body = '<html><head><script src="https://cdn.jsdelivr.net/npm/x.js"></script></head></html>'

        result = sri.audit(body, base_url="https://example.com/")

        self.assertEqual(set(result), self._KEYS)
        self.assertEqual(result["scripts_total"], 1)
        self.assertEqual(result["scripts_external"], 1)
        self.assertEqual(result["scripts_missing_integrity"], 1)
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertTrue(finding["third_party"])
        self.assertEqual(finding["severity"], "medium")
        self.assertIn("Third-party", finding["issue"])
        self.assertEqual(result["score"], 0)

    def test_page_with_no_external_subresources_scores_100(self):
        result = sri.audit("<html><body><h1>hello</h1></body></html>", base_url="https://example.com/")

        self.assertEqual(result["scripts_total"], 0)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["score"], 100)

    def test_same_origin_script_is_informational_only(self):
        result = sri.audit('<html><script src="/app.js"></script></html>', base_url="https://example.com/")

        self.assertEqual(result["scripts_external"], 0)
        self.assertEqual(result["score"], 100)
        self.assertEqual(len(result["findings"]), 1)
        self.assertFalse(result["findings"][0]["third_party"])
        self.assertEqual(result["findings"][0]["severity"], "low")
        self.assertIn("Same-origin", result["findings"][0]["issue"])

    def test_external_with_integrity_and_crossorigin_scores_100(self):
        body = (
            '<html><script src="https://cdn.other.net/lib.js" '
            'integrity="sha384-abc" crossorigin="anonymous"></script></html>'
        )

        result = sri.audit(body, base_url="https://example.com/")

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["crossorigin_missing"], 0)
        self.assertEqual(result["score"], 100)

    def test_integrity_without_crossorigin_is_reported_at_low(self):
        body = '<html><script src="https://cdn.other.net/lib.js" integrity="sha384-abc"></script></html>'

        result = sri.audit(body, base_url="https://example.com/")

        self.assertEqual(result["crossorigin_missing"], 1)
        self.assertEqual(result["score"], 100)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["severity"], "low")
        self.assertIn("no crossorigin attribute", result["findings"][0]["issue"])

    def test_stylesheet_without_integrity_is_counted_separately(self):
        body = '<html><link rel="stylesheet" href="https://cdn.other.net/site.css"></html>'

        result = sri.audit(body, base_url="https://example.com/")

        self.assertEqual(result["stylesheets_total"], 1)
        self.assertEqual(result["stylesheets_external"], 1)
        self.assertEqual(result["stylesheets_missing_integrity"], 1)
        self.assertEqual(result["findings"][0]["type"], "stylesheet")
        self.assertTrue(result["findings"][0]["third_party"])

    def test_missing_base_url_is_stated_and_under_reports(self):
        body = '<html><script src="https://cdn.other.net/lib.js"></script></html>'

        result = sri.audit(body)

        self.assertFalse(result["findings"][0]["third_party"])
        self.assertTrue(any("No base_url supplied" in issue for issue in result["issues"]))

    def test_inline_schemes_are_skipped(self):
        body = '<html><script src="data:text/javascript,alert(1)"></script></html>'

        result = sri.audit(body, base_url="https://example.com/")

        self.assertEqual(result["scripts_total"], 0)
        self.assertEqual(result["score"], 100)

    def test_malformed_input_never_raises(self):
        for value in ("", None, "<html><script"):
            result = sri.audit(value)
            self.assertEqual(set(result), self._KEYS)
            self.assertEqual(result["score"], 100)


class RiskScoringTests(unittest.TestCase):
    """core.risk must consume the v2 exposure payload.

    Regression guard for a silent integration gap: the scorer used to read
    ``enriched["exposure"]`` as a list of ``{"url", "status_code"}`` rows, which
    the v2 exposure module never produces - its payload is a dict of verified
    ``findings`` plus unverified ``candidates``. The factor therefore could not
    fire at all, however many sensitive files were verified.
    """

    _ENV_FINDING = {
        "path": "/.env",
        "status": 200,
        "severity": "critical",
        "kind": "credentials",
        "detail": "dotenv file with 3 assignments",
        "evidence": "DB_PASSWORD=...",
    }

    def _result(self, **enriched):
        result = SimpleNamespace(enriched=dict(enriched))
        # A detected WAF keeps the unrelated `no_waf` factor out of the score.
        result.waf = [{"name": "Cloudflare"}]
        return result

    def _payload(self, findings=(), candidates=()):
        return {
            "base_url": "https://target.example",
            "findings": list(findings),
            "candidates": list(candidates),
            "directory_listing": False,
            "security_txt": {"present": False, "fields": {}, "expired": False},
            "crossdomain": {"present": False, "wildcard": False},
            "source_maps": [],
            "checked": 24,
            "errors": [],
        }

    def test_verified_exposure_finding_scores_the_factor(self):
        scored = score_result(self._result(exposure=self._payload(findings=[self._ENV_FINDING])))

        factors = {factor["factor"]: factor for factor in scored["factors"]}
        self.assertIn("exposed_sensitive_file", factors)
        self.assertEqual(factors["exposed_sensitive_file"]["weight"], 25)
        self.assertIn("/.env", factors["exposed_sensitive_file"]["detail"])
        self.assertGreaterEqual(scored["score"], 25)

    def test_the_old_url_status_code_read_finds_nothing_in_the_v2_payload(self):
        """The bug expressed as an assertion: reading the v2 payload the way the
        scorer used to yields no url and no status_code, so the old code could
        never fire - while the new consumer scores the very same payload."""
        payload = self._payload(findings=[self._ENV_FINDING])

        self.assertIsNone(payload.get("url"))
        self.assertIsNone(payload.get("status_code"))
        scored = score_result(self._result(exposure=payload))
        self.assertIn("exposed_sensitive_file", {factor["factor"] for factor in scored["factors"]})

    def test_unverified_candidates_alone_do_not_score(self):
        """`candidates` are 200s the module could not verify, so they must never
        drive a risk score."""
        payload = self._payload(candidates=[{"path": "/.env", "status": 200, "note": "HTML shell"}])

        scored = score_result(self._result(exposure=payload))

        self.assertNotIn("exposed_sensitive_file", {factor["factor"] for factor in scored["factors"]})
        self.assertEqual(scored["score"], 0)

    def test_informational_and_non_file_findings_do_not_score(self):
        """An absent security.txt is a missing good practice (info), a source map
        and a permissive crossdomain policy are different classes of signal."""
        payload = self._payload(findings=[
            {"path": "/.well-known/security.txt", "status": 404, "severity": "info", "kind": "security_txt"},
            {"path": "/app.js.map", "status": 200, "severity": "low", "kind": "source_map"},
            {"path": "/crossdomain.xml", "status": 200, "severity": "medium", "kind": "crossdomain_policy"},
        ])

        scored = score_result(self._result(exposure=payload))

        self.assertNotIn("exposed_sensitive_file", {factor["factor"] for factor in scored["factors"]})
        self.assertEqual(scored["score"], 0)

    def test_every_verified_file_finding_scores(self):
        payload = self._payload(findings=[
            {"path": "/.git/HEAD", "status": 200, "severity": "high", "kind": "git_disclosure"},
            {"path": "/db.sql", "status": 200, "severity": "high", "kind": "database_dump"},
            {"path": "/.htaccess", "status": 200, "severity": "medium", "kind": "config_disclosure"},
            {"path": "/.DS_Store", "status": 200, "severity": "low", "kind": "metadata_disclosure"},
        ])

        scored = score_result(self._result(exposure=payload))

        self.assertEqual(scored["score"], 100)  # 4 x 25, capped at 100
        scored_factors = [factor for factor in scored["factors"] if factor["factor"] == "exposed_sensitive_file"]
        self.assertEqual(len(scored_factors), 4)
        self.assertIn("/db.sql returned 200 (high)", [factor["detail"] for factor in scored_factors])

    def test_legacy_url_status_code_rows_still_score(self):
        """Defensive: cached results and older producers hand over the old
        shape, so it must keep working."""
        scored = score_result(self._result(exposure=[
            {"url": "https://target.example/.env", "status_code": 200},
        ]))

        self.assertEqual(scored["score"], 25)

    def test_legacy_rows_still_require_a_200_and_a_sensitive_marker(self):
        scored = score_result(self._result(exposure=[
            {"url": "https://target.example/.env", "status_code": 403},
            {"url": "https://target.example/robots.txt", "status_code": 200},
        ]))

        self.assertEqual(scored["score"], 0)

    def test_malformed_exposure_payloads_never_raise(self):
        for value in (None, {}, [], "nope", 7, [None], [{}], {"findings": None}, {"findings": [None]}):
            scored = score_result(self._result(exposure=value))
            self.assertEqual(scored["score"], 0)


if __name__ == "__main__":
    unittest.main()
