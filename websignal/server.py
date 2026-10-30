"""Loopback-only web interface for the existing scanner and AI explainer."""

from copy import deepcopy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .ai import AIError, DEFAULT_MODELS, PROMPT_VERSION, add_ai_sample, explain, preview, validate_report
from .assessment import enrich
from .profile import profile_for_report
from .network import ScanError, normalize_domain, validate_url
from .links import normalize_target, normalize_expected_domain
from .comparison import compare_reports
from .brief import build_brief
from .check_feedback import check_feedback_for_report
from .page_risks import page_risks_for_report
from .reputation import inspect_urls, public_result
from .reports import render
from .scanner import demo_report, community_blocked_report, add_community_result
from . import threat_feed
from .visitor_assessment import build_visitor_assessment


STATIC = Path(__file__).with_name("static")
MAX_JOBS = 20


class WebError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def target_domain(value):
    """Return the hostname for display; scanning preserves the full target."""
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise WebError("Enter a website domain or an HTTP/HTTPS link.")
    value = value.strip()
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise WebError("The website link contains invalid characters.")
    try:
        if "://" in value or "/" in value or "?" in value or "#" in value:
            url = value if "://" in value else "https://" + value
            _, host, _, _ = validate_url(url)
            return host
        return normalize_domain(value)
    except (ScanError, ValueError) as exc:
        raise WebError("Use a public website domain or HTTP/HTTPS link, without a login or custom port.") from exc


def run_scan(target, rdap, expected_domain=None, security_contact=False):
    """A separate process enforces a deadline even if DNS or headers stall."""
    command = [sys.executable, "-m", "websignal", "scan", "--target-stdin", "--format", "json", "--timeout", "7"]
    if expected_domain:
        command.extend(["--expected-domain", expected_domain])
    if rdap:
        command.append("--rdap")
    if security_contact:
        command.append("--security-contact")
    environment = dict(os.environ)
    environment.pop("OPENAI_API_KEY", None)
    environment.pop("GOOGLE_SAFE_BROWSING_API_KEY", None)
    try:
        result = subprocess.run(command, input=target.encode("utf-8"), capture_output=True, timeout=90, env=environment,
                                cwd=str(Path(__file__).resolve().parent.parent), check=False)
    except subprocess.TimeoutExpired as exc:
        raise WebError("The website did not finish responding within 90 seconds. Try again later.") from exc
    if result.returncode not in {0, 1} or len(result.stdout) > 1024 * 1024:
        raise WebError("The scan could not complete. Check the domain and try again.")
    try:
        report = json.loads(result.stdout)
        validate_report(report)
        return report
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise WebError("The scanner returned an incomplete report.") from exc


class AppState:
    def __init__(self):
        self.csrf_token = secrets.token_urlsafe(32)
        self.lock = threading.RLock()
        self.jobs = {}
        self.api_key = ""
        self.reputation_key = ""
        self.reputation_busy = False
        self.provider = "builtin"
        self.scan_busy = False
        self.ai_busy = False

    def config(self):
        with self.lock:
            source = "session" if self.api_key else "environment" if os.environ.get("OPENAI_API_KEY") else None
            reputation_source = "session" if self.reputation_key else "environment" if os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY") else None
            return {"csrf_token": self.csrf_token, "version": __version__,
                    "ai_prompt_version": PROMPT_VERSION,
                    "openai_configured": source is not None, "key_source": source,
                    "reputation_configured": reputation_source is not None, "reputation_key_source": reputation_source,
                    "community_default": True, "community_provider": threat_feed.PROVIDER,
                    "community_source_url": threat_feed.SOURCE_URL, "community_privacy_note": threat_feed.PRIVACY_NOTE,
                    "provider": self.provider, "models": dict(DEFAULT_MODELS),
                    "model": DEFAULT_MODELS.get(self.provider)}

    @staticmethod
    def _validate_key(key):
        if not isinstance(key, str) or (key and (not 20 <= len(key) <= 512 or not key.isascii()
                                                or any(ord(c) < 33 or ord(c) > 126 for c in key))):
            raise WebError("Enter your full OpenAI API key without spaces, or leave it empty to remove the session key.")

    def set_settings(self, body):
        with self.lock:
            provider = body.get("provider", self.provider)
            if not isinstance(provider, str) or provider not in {"builtin", "ollama", "openai"}:
                raise WebError("Choose built-in explanations, local Ollama, or OpenAI.")
            if "api_key" in body:
                self._validate_key(body["api_key"])
            if "reputation_key" in body:
                key = body["reputation_key"]
                if not isinstance(key, str) or (key and (not 20 <= len(key) <= 512 or not key.isascii()
                                                        or any(ord(c) < 33 or ord(c) > 126 for c in key))):
                    raise WebError("Enter a complete Google Safe Browsing API key without spaces.")
            # Validate the whole update before changing either setting.
            if "api_key" in body:
                self.api_key = body["api_key"]
            if "reputation_key" in body:
                self.reputation_key = body["reputation_key"]
            self.provider = provider
            return self.config()

    def set_key(self, key):
        """Compatibility helper for callers explicitly configuring OpenAI."""
        self._validate_key(key)
        with self.lock:
            self.api_key = key
            if key:
                self.provider = "openai"
            return self.config()

    def preview_report(self, report):
        with self.lock:
            provider = self.provider
        if provider == "builtin":
            return {"provider": "builtin", "model": None, "messages": [],
                    "note": "Built-in explanations use recorded checks. No data is sent to an AI provider."}
        return preview(report, provider=provider)

    def job(self, identifier):
        with self.lock:
            if identifier not in self.jobs:
                raise WebError("This report is no longer in this session. Run a new check.", 404)
            snapshot = deepcopy(self.jobs[identifier])
        if snapshot.get("report"):
            snapshot["report"] = enrich(snapshot["report"])
            snapshot["report"]["site_profile"] = profile_for_report(snapshot["report"])
            if snapshot["report"].get("reputation"):
                snapshot["report"]["reputation"] = public_result(snapshot["report"]["reputation"])
            snapshot["report"]["page_risks"] = page_risks_for_report(snapshot["report"])
            snapshot["report"]["community_reputation"] = threat_feed.community_for_report(snapshot["report"])
            snapshot["report"]["visitor_assessment"] = build_visitor_assessment(snapshot["report"])
            snapshot["report"]["brief"] = build_brief(snapshot["report"])
            snapshot["report"]["check_feedback"] = check_feedback_for_report(snapshot["report"])
        return snapshot

    def list_jobs(self):
        with self.lock:
            # Listing history does not duplicate full report bodies.
            return [{k: v for k, v in job.items() if k != "report"} for job in reversed(list(self.jobs.values()))]

    def _new_job(self, domain, report=None):
        if len(self.jobs) >= MAX_JOBS:
            old = next((key for key, job in self.jobs.items()
                        if job["status"] != "running" and job["ai_status"] != "running"
                        and job.get("reputation_status") != "running"), None)
            if old is None:
                raise WebError("This session is busy. Please wait for the current check.", 429)
            del self.jobs[old]
        identifier = secrets.token_hex(12)
        job = {"id": identifier, "domain": domain, "status": "complete" if report else "running",
               "phase": "Report ready" if report else "Following the link and reading its connection, domain and page signals…",
               "report": report, "error": None, "ai_status": "complete" if report and report.get("ai") else "idle",
               "ai_provider": report.get("ai", {}).get("provider") if report else None,
               "ai_error": None, "reputation_status": "idle", "created_at": datetime.now(timezone.utc).isoformat()}
        self.jobs[identifier] = job
        return identifier

    def start_scan(self, target, rdap=True, expected_domain=None, community_check=True, security_contact=False):
        try:
            target = normalize_target(target)
            expected_domain = normalize_expected_domain(expected_domain)
        except (ScanError, ValueError, AttributeError, TypeError) as exc:
            raise WebError(str(exc) if isinstance(exc, ScanError) else "Enter a public link and an optional expected domain.") from exc
        domain = target_domain(target)
        if type(rdap) is not bool:
            raise WebError("The registration lookup option must be true or false.")
        if type(community_check) is not bool:
            raise WebError("The community checking option must be true or false.")
        if type(security_contact) is not bool:
            raise WebError("The security contact option must be true or false.")
        with self.lock:
            if self.scan_busy:
                raise WebError("A website check is already running. Wait for it to finish.", 409)
            identifier = self._new_job(domain)
            self.jobs[identifier]["target_url"] = target
            self.scan_busy = True
        threading.Thread(target=self._scan_worker, args=(identifier, target, rdap, expected_domain, community_check, security_contact), daemon=True).start()
        return self.job(identifier)

    def _scan_worker(self, identifier, target, rdap, expected_domain=None, community_check=False, security_contact=False):
        try:
            community = threat_feed.inspect_urls([target], enabled=community_check)
            if community["status"] == "listed":
                report = community_blocked_report(target, community, expected_domain, security_contact)
            else:
                if security_contact:
                    report = run_scan(target, rdap, expected_domain, security_contact=True)
                else:
                    report = run_scan(target, rdap, expected_domain) if expected_domain else run_scan(target, rdap)
                report = add_community_result(report, enabled=community_check)
            with self.lock:
                for previous in reversed(list(self.jobs.values())):
                    if previous["id"] != identifier and previous.get("report") and not previous["report"].get("demo"):
                        comparison = compare_reports(previous["report"], report)
                        if comparison["available"]:
                            report["comparison"] = comparison
                            break
                self.jobs[identifier].update(status="complete", report=report, phase="Report ready")
        except Exception as exc:
            message = str(exc) if isinstance(exc, WebError) else "The check stopped unexpectedly. Try again."
            with self.lock:
                self.jobs[identifier].update(status="failed", error=message, phase="Check could not finish")
        finally:
            with self.lock:
                self.scan_busy = False

    def demo(self):
        with self.lock:
            identifier = self._new_job("demo.example.com", add_ai_sample(demo_report()))
            return self.job(identifier)

    def compare(self, identifier, previous=None):
        """Compare observations locally; imported JSON is never scanned or sent out."""
        with self.lock:
            job = self.job(identifier)
            if not job.get("report"):
                raise WebError("Finish the check before comparing reports.", 409)
            if previous is not None:
                try:
                    validate_report(previous)
                except (AIError, ValueError, TypeError, RecursionError) as exc:
                    raise WebError("Choose a valid Verifact JSON report.") from exc
                comparison = compare_reports(previous, job["report"])
            else:
                comparison = {"available": False, "reason": "No earlier report for this exact link is in this session.", "changes": []}
                for item in reversed(list(self.jobs.values())):
                    if item["id"] != identifier and item.get("report") and item["created_at"] < job["created_at"]:
                        candidate = compare_reports(item["report"], job["report"])
                        if candidate["available"]:
                            comparison = candidate
                            break
            if not comparison["available"]:
                raise WebError(comparison.get("reason") or "These reports cannot be compared.")
            self.jobs[identifier]["report"]["comparison"] = comparison
            return self.job(identifier)

    def start_reputation(self, identifier, consent=False):
        if consent is not True:
            raise WebError("Confirm sending this link and its observed redirects to Google for a threat lookup.")
        with self.lock:
            job = self.job(identifier)
            report = job.get("report")
            if job["status"] != "complete" or not report:
                raise WebError("Finish a link check before a threat lookup.", 409)
            if report.get("demo"):
                raise WebError("The sample is synthetic. Check a public link to use the threat lookup.")
            if job.get("reputation_status") == "running":
                return job
            if self.reputation_busy:
                raise WebError("A threat lookup is already running. Please wait.", 409)
            key = self.reputation_key or os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
            if not key:
                raise WebError("Add your Google Safe Browsing key in Settings first. The other checks work without it.")
            analysis = report.get("link_analysis") or {}
            values = [report.get("target_url") or "https://" + report["domain"] + "/"]
            values.extend(item.get("url") for item in analysis.get("redirects", []))
            values.append(analysis.get("final_url") or (report.get("response") or {}).get("url"))
            urls = list(dict.fromkeys(value for value in values if isinstance(value, str) and value))
            self.jobs[identifier]["reputation_status"] = "running"
            self.reputation_busy = True
        threading.Thread(target=self._reputation_worker, args=(identifier, urls, key), daemon=True).start()
        return self.job(identifier)

    def _reputation_worker(self, identifier, urls, key):
        try:
            result = inspect_urls(urls, api_key=key, timeout=8)
        except Exception:
            result = {"provider": "Google Safe Browsing", "status": "unavailable", "checked_count": 0,
                      "checked_at": None, "matches": [], "detail": "The lookup could not complete. No threat verdict was established."}
        with self.lock:
            self.jobs[identifier]["report"]["reputation"] = result
            self.jobs[identifier]["reputation_status"] = "complete"
            self.reputation_busy = False

    def start_ai(self, identifier, refresh=False):
        if type(refresh) is not bool:
            raise WebError("The explanation update option must be true or false.")
        with self.lock:
            job = self.job(identifier)
            if job["status"] != "complete" or not job["report"]:
                raise WebError("Finish a website check before generating explanations.", 409)
            stored_ai = job["report"].get("ai")
            if job["report"].get("demo") or (isinstance(stored_ai, dict) and stored_ai.get("fixture")):
                raise WebError("The demo already includes illustrative explanations. Check a real domain to use AI.")
            if job["ai_status"] == "running":
                return job  # Repeated update clicks cannot duplicate a running request.
            stale = isinstance(stored_ai, dict) and stored_ai.get("prompt_version") != PROMPT_VERSION
            if (isinstance(stored_ai, dict) or job["ai_status"] == "complete") and not (refresh and stale):
                return job  # A current or existing answer is reused unless an older one is explicitly updated.
            if self.ai_busy:
                raise WebError("An AI explanation is already running. Please wait.", 409)
            provider = self.provider
            if provider == "builtin":
                raise WebError("Built-in explanations are already included. Select an optional AI provider in AI options.")
            key = (self.api_key or os.environ.get("OPENAI_API_KEY", "")) if provider == "openai" else None
            if provider == "openai" and not key:
                raise WebError("Configure your own OpenAI API key in AI options or choose local Ollama.")
            self.jobs[identifier].update(ai_status="running", ai_error=None, ai_provider=provider)
            self.ai_busy = True
        threading.Thread(target=self._ai_worker, args=(identifier, job["report"], key, provider), daemon=True).start()
        return self.job(identifier)

    def _ai_worker(self, identifier, report, key, provider="openai"):
        try:
            enriched = explain(report, provider=provider, api_key=key, timeout=120 if provider == "ollama" else 60)
            with self.lock:
                # Another optional lookup may have completed during generation.
                self.jobs[identifier]["report"]["ai"] = enriched["ai"]
                self.jobs[identifier]["ai_status"] = "complete"
        except Exception as exc:
            message = str(exc) if isinstance(exc, AIError) else "AI explanations could not be generated. Your scan results are still available."
            with self.lock:
                self.jobs[identifier].update(ai_status="failed", ai_error=message)
        finally:
            with self.lock:
                self.ai_busy = False


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, state=None):
        if address[0] != "127.0.0.1":
            raise ValueError("Verifact's web interface must bind to 127.0.0.1.")
        self.state = state or AppState()
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = "Verifact"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format, *args):
        # Do not log request bodies, submitted targets, keys or arbitrary URLs.
        pass

    def _guard(self, mutating=False):
        port = self.server.server_address[1]
        allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        host = self.headers.get("Host", "")
        if host not in allowed_hosts:
            raise WebError("Open Verifact through its local address.", 403)
        origin = self.headers.get("Origin")
        if origin is not None and origin != "http://" + host:
            raise WebError("Requests must come from the local Verifact page.", 403)
        # A normal link may open the public app shell from another page or a
        # local source file. API requests and embedded documents stay blocked.
        public_navigation = (not mutating and self.command == "GET" and self.path == "/"
                             and origin is None
                             and self.headers.get("Sec-Fetch-Mode") == "navigate"
                             and self.headers.get("Sec-Fetch-Dest") == "document")
        if self.headers.get("Sec-Fetch-Site") == "cross-site" and not public_navigation:
            raise WebError("Cross-site requests are blocked.", 403)
        if mutating and not secrets.compare_digest(self.headers.get("X-WebSignal-Token", ""), self.server.state.csrf_token):
            raise WebError("Session expired. Refresh the page and try again.", 403)

    def _send(self, body, content_type="application/json; charset=utf-8", status=200, attachment=None):
        if not isinstance(body, bytes):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.end_headers()
        self.wfile.write(body)

    def _json(self, value, status=200):
        self._send(json.dumps(value, ensure_ascii=False), status=status)

    def _body(self):
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            raise WebError("This endpoint accepts JSON only.", 415)
        if self.headers.get("Transfer-Encoding"):
            raise WebError("Chunked request bodies are not supported.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise WebError("Invalid request length.") from exc
        limit = 1024 * 1024 if re.fullmatch(r"/api/scans/[a-f0-9]{24}/compare", self.path) else 8192
        if not 0 < length <= limit:
            raise WebError("Request is empty or exceeds this endpoint’s size limit.", 413)
        try:
            value = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise WebError("Request is not valid JSON.") from exc
        if not isinstance(value, dict):
            raise WebError("Request body must be an object.")
        return value

    def do_GET(self):
        self._dispatch(False)

    def do_POST(self):
        self._dispatch(True)

    def _dispatch(self, post):
        try:
            self._guard(post)
            path = urlsplit(self.path).path
            state = self.server.state
            if post:
                body = self._body()
                if path == "/api/settings":
                    return self._json(state.set_settings(body))
                if path == "/api/scans":
                    return self._json(state.start_scan(body.get("target"), body.get("rdap", True), body.get("expected_domain"), body.get("community_check", True), body.get("security_contact", False)), 202)
                if path == "/api/demo":
                    return self._json(state.demo())
                match = re.fullmatch(r"/api/scans/([a-f0-9]{24})/explain", path)
                if match:
                    return self._json(state.start_ai(match[1], refresh=body.get("refresh", False)), 202)
                match = re.fullmatch(r"/api/scans/([a-f0-9]{24})/reputation", path)
                if match:
                    return self._json(state.start_reputation(match[1], consent=body.get("consent", False)), 202)
                match = re.fullmatch(r"/api/scans/([a-f0-9]{24})/compare", path)
                if match:
                    if "previous" in body and not isinstance(body["previous"], dict):
                        raise WebError("Choose a valid Verifact JSON report.")
                    return self._json(state.compare(match[1], previous=body.get("previous")))
            else:
                if path == "/":
                    return self._send((STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
                assets = {"/assets/app.css": ("app.css", "text/css; charset=utf-8"),
                          "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
                          "/assets/report_view.js": ("report_view.js", "text/javascript; charset=utf-8"),
                          "/assets/fonts/SpaceGrotesk.ttf": ("fonts/SpaceGrotesk.ttf", "font/ttf"),
                          "/assets/fonts/IBMPlexMono-Regular.ttf": ("fonts/IBMPlexMono-Regular.ttf", "font/ttf")}
                # Relative URLs also let a directly opened source file show its
                # launch instructions. Keep the explicit asset allowlist.
                assets.update({path.removeprefix("/assets"): value for path, value in list(assets.items())})
                if path in assets:
                    file, mime = assets[path]
                    return self._send((STATIC / file).read_bytes(), mime)
                if path == "/api/config":
                    return self._json(state.config())
                if path == "/api/scans":
                    return self._json({"scans": state.list_jobs()})
                match = re.fullmatch(r"/api/scans/([a-f0-9]{24})(?:/(download|preview))?", path)
                if match:
                    job = state.job(match[1])
                    if not match[2]:
                        return self._json(job)
                    report = job["report"]
                    if not report:
                        raise WebError("The report is not ready yet.", 409)
                    if match[2] == "preview":
                        return self._json(state.preview_report(report))
                    format = parse_qs(urlsplit(self.path).query).get("format", ["json"])[0]
                    if format not in {"html", "json"}:
                        raise WebError("Choose HTML or JSON for the download.")
                    mime = "text/html; charset=utf-8" if format == "html" else "application/json; charset=utf-8"
                    return self._send(render(report, format), mime, attachment=f"verifact-{job['domain']}.{format}")
            raise WebError("Not found.", 404)
        except WebError as exc:
            self._json({"error": str(exc)}, exc.status)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            return
        except Exception:
            self._json({"error": "The app could not complete this request. Refresh and try again."}, 500)


def serve(port=8765, open_browser=False):
    server = AppServer(("127.0.0.1", port))
    url = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"Verifact is running at {url}", flush=True)
    print("Open this address in your browser. Press Ctrl+C to stop. Session keys and reports are kept in memory.", flush=True)
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        print("\nVerifact stopped.", flush=True)
    finally:
        server.server_close()
    return 0
