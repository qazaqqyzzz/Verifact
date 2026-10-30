import json
import socket
import unittest
from unittest.mock import Mock, patch

from websignal.checks import page_checks
from websignal.network import Client, Fetch, Response
from websignal.profile import profile_for_report, site_profile
from websignal.scanner import finish_report


def response(body="", **kwargs):
    return Response("https://example.com/login", 200, {"content-type": "text/html; charset=utf-8"},
                    body.encode(), **kwargs)


def check(html, identifier="password_forms", **kwargs):
    return next(item for item in page_checks(response(html, **kwargs)) if item["id"] == identifier)


class PasswordFormTests(unittest.TestCase):
    def test_relative_post_and_empty_action_are_observed_without_submission(self):
        for action in ('action="/auth"', 'action=""', ''):
            with self.subTest(action=action):
                item = check('<base href="https://elsewhere.example/"><form method="post" ' + action +
                             '><input type="password" name="password"></form>')
                if action == 'action="/auth"':
                    self.assertEqual(item["status"], "attention")
                    self.assertEqual(item["evidence"]["cross_origin_actions"], 1)
                    self.assertEqual(item["evidence"]["destinations"][0]["hostname"], "elsewhere.example")
                else:
                    self.assertEqual(item["status"], "pass")
                    self.assertEqual(item["evidence"]["destinations"][0]["hostname"], "example.com")

    def test_first_base_applies_and_get_is_recorded(self):
        item = check('<base href="http://login.example/"><base href="https://example.com/">'
                     '<form action="submit"><input name="pw" type="password"></form>')
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["http_actions"], 1)
        self.assertEqual(item["evidence"]["get_submissions"], 1)
        self.assertEqual(item["evidence"]["cross_origin_actions"], 1)

    def test_international_hosts_compare_as_same_origin_without_deviation_mapping(self):
        body = '<form method="post" action="https://bücher.example/login"><input name="pw" type="password"></form>'
        page = Response("https://xn--bcher-kva.example/", 200, {"content-type": "text/html"}, body.encode())
        item = next(item for item in page_checks(page) if item["id"] == "password_forms")
        self.assertEqual(item["status"], "pass")
        self.assertEqual(item["evidence"]["cross_origin_actions"], 0)
        self.assertEqual(item["evidence"]["destinations"][0]["hostname"], "xn--bcher-kva.example")
        ambiguous = check('<form method="post" action="https://faß.example/login"><input name="pw" type="password"></form>')
        self.assertEqual(ambiguous["status"], "unknown")

    def test_explicit_port_zero_is_not_replaced_with_https_default(self):
        item = check('<form method="post" action="https://example.com:0/login"><input name="pw" type="password"></form>')
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["cross_origin_actions"], 1)
        self.assertFalse(item["evidence"]["destinations"][0]["same_origin"])
        self.assertEqual(item["evidence"]["destinations"][0]["port"], 0)

    def test_whitespace_action_and_override_resolve_against_base(self):
        for form in ['<form method="post" action=" "><input name="pw" type="password"></form>',
                     '<form method="post"><input name="pw" type="password"><button formaction=" ">Send</button></form>']:
            with self.subTest(form=form):
                item = check('<base href="http://other.example/">' + form)
                self.assertEqual(item["status"], "attention")
                self.assertEqual(item["evidence"]["http_actions"], 1)
                self.assertEqual(item["evidence"]["cross_origin_actions"], 1)
        empty = check('<base href="http://other.example/"><form method="post" action=""><input name="pw" type="password"></form>')
        self.assertEqual(empty["status"], "pass")

    def test_external_association_and_submit_overrides(self):
        item = check('<form id="auth" action="/auth" method="post"></form>'
                     '<input form="auth" type="password" name="pw">'
                     '<button form="auth" formaction="http://other.example/submit?secret=private" formmethod="get">Submit</button>')
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["forms_with_password"], 1)
        self.assertEqual(item["evidence"]["http_actions"], 1)
        self.assertEqual(item["evidence"]["get_submissions"], 1)
        self.assertNotIn("private", json.dumps(item))
        self.assertNotIn("?secret", json.dumps(item))

    def test_unavailable_or_incomplete_html_is_unknown(self):
        body = '<form action="http://other.example"><input name="pw" type="password">'
        self.assertEqual(check(body, truncated=True)["status"], "unknown")
        for candidate in [None, Response("https://example.com/", 403, {"content-type": "text/html"}, body.encode()),
                          Response("https://example.com/", 200, {"content-type": "application/json"}, b"{}")]:
            item = next(item for item in page_checks(candidate) if item["id"] == "password_forms")
            self.assertEqual(item["status"], "unknown")

    def test_no_forms_is_observation_and_unowned_or_unnamed_fields_unknown(self):
        self.assertEqual(check('<p>Welcome</p>')["status"], "info")
        self.assertEqual(check('<input type="password" name="pw">')["status"], "unknown")
        self.assertEqual(check('<form method="post"><input type="password"></form>')["status"], "unknown")
        self.assertEqual(check('<form method="post"><input type="password" name="pw" disabled></form>')["status"], "info")
        self.assertEqual(check('<template><form><input type="password" name="pw"></form></template>')["status"], "info")

    def test_unsupported_actions_and_ambiguous_markup_never_pass(self):
        for body in ['<form method="post" action="javascript:submit()"><input type="password" name="pw"></form>',
                     '<form method="post"><fieldset disabled><input type="password" name="pw"></fieldset></form>',
                     '<form method="post"><form><input type="password" name="pw"></form></form>',
                     '<div id="auth"></div><form id="auth" method="post"></form><input form="auth" type="password" name="pw">']:
            with self.subTest(body=body):
                self.assertEqual(check(body)["status"], "unknown")

    def test_invalid_method_and_button_type_use_html_defaults(self):
        item = check('<form method=" post "><input name="pw" type="password"></form>')
        self.assertEqual(item["evidence"]["get_submissions"], 1)
        item = check('<form method="post"><input name="pw" type="password">'
                     '<button type="invalid" formaction="http://elsewhere.example/">Send</button></form>')
        self.assertEqual(item["evidence"]["http_actions"], 1)


class CookieObservationTests(unittest.TestCase):
    def test_actual_client_keeps_duplicate_cookie_fields_and_redacts_report(self):
        sock, connection, incoming = Mock(), Mock(), Mock(status=200)
        incoming.getheaders.return_value = [
            ("Content-Type", "text/html"),
            ("Set-Cookie", "session=SECRET_SESSION; Expires=Wed, 21 Oct 2030 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax"),
            ("Set-Cookie", "theme=SECRET_THEME; Secure; SameSite=Strict")]
        incoming.read1.side_effect = [b"<title>Example</title>", b""]
        connection.getresponse.return_value = incoming
        public = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 80))
        with patch("websignal.network.socket.getaddrinfo", return_value=[public]), \
             patch("websignal.network.socket.socket", return_value=sock), \
             patch("websignal.network.http.client.HTTPConnection", return_value=connection):
            observed = Client().request("http://example.com/")
        self.assertEqual(len(observed.set_cookie_headers), 2)
        self.assertNotIn("set-cookie", observed.headers)
        report = finish_report("example.com", Fetch(observed), Fetch(observed), 1)
        encoded = json.dumps(report)
        self.assertNotIn("SECRET_SESSION", encoded)
        self.assertNotIn("SECRET_THEME", encoded)
        cookie = next(item for item in report["findings"] if item["id"] == "cookie_flags")
        self.assertEqual(cookie["status"], "info")
        self.assertEqual(cookie["evidence"]["cookies_observed"], 2)
        self.assertEqual(cookie["evidence"]["missing_http_only"], 1)
        self.assertEqual([item["name"] for item in cookie["evidence"]["cookies"]], ["session", "theme"])

    def test_missing_secure_attention_and_optional_attributes_informational(self):
        item = check('', "cookie_flags", set_cookie_headers=["sid=SECRET; HttpOnly; SameSite=None"])
        self.assertEqual(item["status"], "attention")
        self.assertEqual(item["evidence"]["same_site_none_without_secure"], 1)
        self.assertNotIn("SECRET", json.dumps(item))
        self.assertEqual(check('', "cookie_flags", set_cookie_headers=["preferences=SECRET; Secure"])["status"], "info")
        self.assertEqual(check('', "cookie_flags", set_cookie_headers=["sid=SECRET; Secure; HttpOnly; SameSite=Lax"])["status"], "pass")
        self.assertEqual(check('', "cookie_flags", set_cookie_headers=[])["status"], "info")

    def test_malformed_and_limited_cookie_observations_never_pass(self):
        for fields in [["broken"], ["sid=SECRET; Secure, second=SECRET"], ["sid=" + "x" * 9000],
                       ["sid=SECRET; Secure; HttpOnly; SameSite=Lax"] * 51]:
            with self.subTest(fields=len(fields)):
                item = check('', "cookie_flags", set_cookie_headers=fields)
                self.assertEqual(item["status"], "unknown")
                self.assertNotIn("SECRET", json.dumps(item))


class SiteProfileTests(unittest.TestCase):
    def test_metadata_is_bounded_and_classification_is_cautious(self):
        profile = site_profile(response('<title>Student portal</title><meta name="description" content="University resources">'), "example.com")
        self.assertEqual(profile["type"], "Education website")
        self.assertIn("not independently verified", profile["basis"])
        self.assertEqual(profile["description"], "University resources")
        account = site_profile(response('<title>Register</title><input type="password">'))
        self.assertEqual(account["type"], "Account access page")
        self.assertIn("registration", account["basis"])
        long = site_profile(response('<title>' + 'x' * 2000 + '</title><meta name="description" content="' + 'y' * 1000 + '">'))
        self.assertEqual(len(long["title"]), 250)
        self.assertEqual(len(long["description"]), 320)

    def test_domain_names_and_incomplete_metadata_do_not_classify_identity(self):
        profile = site_profile(response('<title>Welcome</title>'), "university.example")
        self.assertEqual(profile["type"], "Website")
        incomplete = site_profile(response('<title>University</title>', truncated=True))
        self.assertEqual(incomplete["type"], "Website")
        self.assertIn("incomplete", incomplete["basis"])
        self.assertEqual(site_profile(None, "university.example")["hostname"], "university.example")

    def test_saved_report_fallback_does_not_invent_missing_description(self):
        report = {"domain": "university.example", "response": {"url": "https://other.example/", "status": 200},
                  "findings": [{"id": "title", "status": "pass", "evidence": "Log in"}]}
        profile = profile_for_report(report)
        self.assertEqual(profile["title"], "Log in")
        self.assertEqual(profile["type"], "Login page")
        self.assertIn("appears", profile["summary"])
        self.assertIn("not established", profile["summary"])
        self.assertEqual(profile["description"], "")
        self.assertEqual(profile["hostname"], "other.example")


if __name__ == "__main__":
    unittest.main()
