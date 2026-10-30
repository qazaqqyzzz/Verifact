"""Purpose descriptions require combined cues; raw page text is not retained."""

import json
import unittest
from unittest.mock import patch

from websignal.checks import read_page
from websignal.network import Response, Fetch
from websignal.profile import PROFILE_VERSION, profile_for_report, site_profile
from websignal.scanner import finish_report


def page(body, host="lms.example.edu.kz", **kwargs):
    return Response("https://" + host + "/login/index.php", 200,
                    {"content-type": "text/html; charset=utf-8"}, body.encode(), **kwargs)


class DescriptionTests(unittest.TestCase):
    def test_academic_lms_with_login_password_evidence_gets_useful_description(self):
        response = page('<title>Log in to the site | frontpage</title><form method="post"><input type="password" name="password"></form>')
        result = site_profile(response)
        self.assertEqual(result["type"], "University login page")
        self.assertIn("appears to be a university login page", result["summary"])
        self.assertIn("learning platform", result["summary"])
        self.assertIn("not inspected", result["summary"])
        self.assertEqual(result["description"], "")
        self.assertTrue(any("password field" in item.lower() for item in result["signals"]))
        self.assertTrue(any(".edu.kz" in item for item in result["signals"]))
        self.assertEqual(result["profile_version"], PROFILE_VERSION)

    def test_visible_headings_and_platform_metadata_help_identify_a_portal(self):
        response = page('<head><title>Welcome</title><meta name="generator" content="Moodle 4"></head>'
                        '<body><h1>Example University learning platform</h1><p>Student courses</p></body>', "portal.example.org")
        result = site_profile(response)
        self.assertEqual(result["type"], "University learning portal")
        self.assertIn("learning-management system", result["summary"])
        self.assertNotIn("Moodle 4", json.dumps(result))

    def test_domain_alone_and_suffix_spoofing_do_not_assert_university_purpose(self):
        response = page('<title>Welcome</title><p>Public page</p>')
        self.assertEqual(site_profile(response)["type"], "Website")
        spoof = page('<title>Log in</title><input type="password">', "lms.example.edu.kz.attacker.com")
        self.assertEqual(site_profile(spoof)["type"], "Login page")
        self.assertFalse(any("academic-style" in item for item in site_profile(spoof)["signals"]))

    def test_school_lms_is_not_labeled_as_university(self):
        response = page('<title>Log in - Example High School</title><input type="password">')
        self.assertEqual(site_profile(response)["type"], "Education login page")

    def test_registration_and_password_recovery_are_not_login_pages(self):
        for title, fragment in [("Register", "registration"), ("Reset your password", "password-recovery")]:
            with self.subTest(title=title):
                result = site_profile(page('<title>' + title + '</title><input type="password">'))
                self.assertEqual(result["type"], "Account access page")
                self.assertIn(fragment, result["summary"])

    def test_excluded_text_and_input_values_cannot_classify_or_leak(self):
        html = ('<title>Welcome</title><script>University login SECRET_SCRIPT</script>'
                '<style>university login SECRET_STYLE</style><template><h1>University login</h1>'
                '<meta name="generator" content="Moodle"></template>'
                '<noscript>University login SECRET_NOSCRIPT</noscript>'
                '<div hidden><h1>University login SECRET_HIDDEN</h1></div>'
                '<div aria-hidden="true">University login</div>'
                '<div style="display: none"><h2>University login</h2></div>'
                '<textarea>University login SECRET_TEXTAREA</textarea>'
                '<input value="University login SECRET_INPUT">'
                '<p>password: SECRET_VALUE University login</p><p>Welcome visitor</p>')
        response = page(html, "example.com")
        parsed, _, _ = read_page(response)
        self.assertNotIn("SECRET", parsed.profile_text)
        self.assertNotIn("University", parsed.profile_text)
        self.assertEqual(parsed.profile_generator, "")
        result = site_profile(response)
        self.assertEqual(result["type"], "Website")
        report = finish_report("example.com", Fetch(response), Fetch(response), 0, demo=True)
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertNotIn("profile_text", json.dumps(report))

    def test_collected_text_and_serialized_profile_are_bounded(self):
        response = page('<h1>' + 'x' * 10000 + '</h1><p>' + 'y' * 12000 + '</p>')
        parsed, _, _ = read_page(response)
        self.assertLessEqual(len(parsed.profile_text), 6000)
        self.assertLessEqual(len(parsed.profile_headings), 1600)
        self.assertLess(len(json.dumps(site_profile(response))), 2000)

    def test_incomplete_page_does_not_overstate_its_purpose(self):
        result = site_profile(page('<title>University login</title><input type="password">', truncated=True))
        self.assertEqual(result["type"], "Account access page")
        self.assertIn("incomplete", result["summary"])
        self.assertIn("uncertain", result["summary"])
        self.assertTrue(site_profile(None)["summary"])

    def test_old_report_upgrade_uses_retained_metadata_without_network(self):
        report = {"domain": "lms.example.edu.kz", "response": {"url": "https://lms.example.edu.kz/login/index.php", "status": 200},
                  "findings": [{"id": "title", "status": "pass", "evidence": "Log in to the site | frontpage"},
                               {"id": "password_forms", "evidence": {"password_inputs": 1}}],
                  "site_profile": {"type": "Account access page", "title": "Log in to the site | frontpage", "description": ""}}
        with patch("websignal.network.Client.fetch") as fetch:
            result = profile_for_report(report)
            fetch.assert_not_called()
        self.assertEqual(result["type"], "University login page")
        self.assertIn("saved report", result["basis"])
        self.assertEqual(result["profile_version"], PROFILE_VERSION)

    def test_unknown_title_error_is_not_used_as_a_page_title(self):
        report = {"domain": "unavailable.example", "response": None,
                  "findings": [{"id": "title", "status": "unknown", "evidence": "No final HTTPS response"}]}
        result = profile_for_report(report)
        self.assertEqual(result["title"], "")
        self.assertEqual(result["type"], "Website")
        self.assertNotIn("No final HTTPS response", result["summary"])

    def test_current_version_retains_summary_and_signals(self):
        profile = site_profile(page('<title>Log in</title><input type="password">'))
        report = {"site_profile": profile, "domain": "lms.example.edu.kz", "findings": []}
        self.assertEqual(profile_for_report(report), profile)
        report["site_profile"]["summary"] = "x" * 1000
        report["site_profile"]["signals"] = ["x" * 1000] * 20
        bounded = profile_for_report(report)
        self.assertEqual(len(bounded["summary"]), 600)
        self.assertEqual(len(bounded["signals"]), 6)
        self.assertTrue(all(len(value) == 200 for value in bounded["signals"]))

    def test_russian_and_kazakh_metadata_identify_an_education_platform(self):
        for description in ("Kundelik.kz — Цифровая образовательная платформа Казахстана",
                            "Қазақстанның цифрлық білім беру платформасы"):
            with self.subTest(description=description):
                result = site_profile(page('<title>Kundelik.kz</title><meta name="description" content="'
                                           + description + '">', "portal.example.kz"))
                self.assertEqual(result["type"], "Education platform")
                self.assertIn("page's own description", result["summary"])
                self.assertIn("not independently verified", result["summary"])
                self.assertNotIn("university", result["summary"].lower())
                self.assertNotIn("learning-management system", result["summary"])

    def test_security_training_purpose_is_not_replaced_by_embedded_login(self):
        response = page('<title>Training Lab</title><meta name="description" content="A free, safe and legal '
                        'training ground for hackers to test and expand skills with challenges and CTFs.">'
                        '<h1>Training Lab</h1><aside><h2>Login</h2><input type="password"></aside>', "lab.example.com")
        result = site_profile(response)
        self.assertEqual(result["type"], "Security training website")
        self.assertIn("also includes account access", result["summary"])
        self.assertIn("access rules", result["summary"])
        # The site's self-description is not an endorsement of legality or safety.
        self.assertNotIn("safe and legal", result["summary"])

    def test_programming_language_metadata_overrides_sidebar_news(self):
        response = page('<title>About Cedar | Cedar.org</title>'
                        '<meta name="description" content="The official home of the Cedar Programming Language">'
                        '<h1>About Cedar</h1><aside><h2>Latest News</h2></aside>'
                        '<footer><h3>Log in</h3><a href="/login">Sign in</a></footer>', "cedar.example.org")
        profile = site_profile(response)
        self.assertEqual(profile["type"], "Software & developer website")
        self.assertIn("programming language", profile["summary"])
        self.assertIn("not verified", profile["summary"])
        self.assertFalse(any("sign-in wording" in signal for signal in profile["signals"]))

    def test_news_and_login_sidebar_headings_do_not_define_page_purpose(self):
        result = site_profile(page('<title>Our product</title><h1>Make something useful</h1>'
                                   '<aside><h2>Latest news</h2></aside><footer><h3>Log in</h3></footer>', "product.example.com"))
        self.assertEqual(result["type"], "Website")
        self.assertNotIn("account login", result["summary"])
        self.assertNotIn("news or publishing", result["summary"])

    def test_explicit_news_title_and_login_title_still_classify(self):
        news = site_profile(page('<title>Daily News for developers</title>'
                                 '<meta name="description" content="Reporting on the Cedar programming language">', "news.example.com"))
        self.assertEqual(news["type"], "News website")
        login = site_profile(page('<title>Log in to Cedar</title><h1>Welcome</h1>', "accounts.example.com"))
        self.assertEqual(login["type"], "Login page")

    def test_saved_v3_navigation_false_positive_is_upgraded_from_metadata(self):
        existing = {"title": "About Cedar", "description": "The home of the Cedar programming language",
                    "type": "News website", "summary": "This appears to be a news website.",
                    "profile_version": "site-profile-v3", "hostname": "cedar.example.org", "https": True, "http_status": 200}
        report = {"domain": "cedar.example.org", "site_profile": existing, "findings": [],
                  "response": {"url": "https://cedar.example.org/about/", "status": 200}}
        with patch("websignal.network.Client.fetch") as fetch:
            upgraded = profile_for_report(report)
            fetch.assert_not_called()
        self.assertEqual(upgraded["type"], "Software & developer website")
        self.assertEqual(upgraded["profile_version"], PROFILE_VERSION)
        existing.update(title="Our product", description="", type="Login page", summary="An account login page.")
        self.assertEqual(profile_for_report(report)["type"], "Website")

    def test_explicit_login_title_stays_login_on_an_education_platform(self):
        result = site_profile(page('<title>Кіру</title><meta name="description" '
                                   'content="Қазақстанның білім беру платформасы"><input type="password">', "example.kz"))
        self.assertEqual(result["type"], "Education login page")
        for title in ("Вход — Средняя школа", "Кіру — Мектеп"):
            with self.subTest(title=title):
                school = site_profile(page('<title>' + title + '</title><input type="password">'))
                self.assertEqual(school["type"], "Education login page")
        reset = site_profile(page('<title>Құпия сөзді қалпына келтіру</title><input type="password">'))
        self.assertIn("password-recovery", reset["summary"])

    def test_footer_students_link_is_not_an_education_purpose_signal(self):
        result = site_profile(page('<title>Build software together</title><p>Collaborate on code.</p>'
                                   '<footer><a href="/students">Students</a></footer>', "code.example.com"))
        self.assertEqual(result["type"], "Website")
        self.assertFalse(any("Education-related" in signal for signal in result["signals"]))

    def test_v2_saved_profile_upgrade_uses_metadata_and_preserves_missing_body_cues(self):
        existing = {"title": "Kundelik.kz", "description": "Цифровая образовательная платформа Казахстана",
                    "type": "Website", "summary": "This is a public webpage.", "profile_version": "site-profile-v2",
                    "hostname": "portal.example.kz", "https": True, "http_status": 200}
        report = {"domain": "portal.example.kz", "site_profile": existing, "findings": [],
                  "response": {"url": "https://portal.example.kz/", "status": 200, "body_truncated": False}}
        with patch("websignal.network.Client.fetch") as fetch:
            upgraded = profile_for_report(report)
            fetch.assert_not_called()
        self.assertEqual(upgraded["type"], "Education platform")
        self.assertEqual(upgraded["profile_version"], PROFILE_VERSION)

        earlier = site_profile(page('<title>Welcome</title><h1>Example University learning platform</h1>', "portal.example.org"))
        earlier["profile_version"] = "site-profile-v2"
        retained = profile_for_report({"site_profile": earlier, "findings": [],
                                       "response": {"url": "https://portal.example.org/", "status": 200}})
        self.assertEqual(retained["type"], "University learning portal")
        self.assertEqual(retained["summary"], earlier["summary"])
        self.assertEqual(retained["profile_version"], PROFILE_VERSION)


if __name__ == "__main__":
    unittest.main()
