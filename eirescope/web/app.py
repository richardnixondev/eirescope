"""EireScope Web Server — Lightweight HTTP server with Jinja2 templates."""
import os
import sys
import json
import logging
import mimetypes
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from jinja2 import Environment, FileSystemLoader

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from eirescope.core.engine import InvestigationEngine
from eirescope.core.results import summarize_investigation
from eirescope.db.database import Database

logger = logging.getLogger("eirescope.web")

# Paths
WEB_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(WEB_DIR, "templates")
STATIC_DIR = os.path.join(WEB_DIR, "static")
DATA_DIR = os.path.join(os.path.dirname(WEB_DIR), "data")

# Initialize Jinja2
jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=True,
)

# Initialize core components — always use /tmp for SQLite (avoids filesystem restrictions)
import tempfile
_db_path = os.path.join(tempfile.gettempdir(), "eirescope_investigations.db")
db = Database(_db_path)
engine = InvestigationEngine()


class EireScopeHandler(BaseHTTPRequestHandler):
    """HTTP Request handler for EireScope web interface."""

    def log_message(self, format, *args):
        logger.info(f"{self.client_address[0]} - {format % args}")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Static files
        if path.startswith("/static/"):
            self._serve_static(path[8:])
            return

        # Routes
        if path == "/" or path == "":
            self._handle_index()
        elif path.startswith("/investigation/"):
            inv_id = path.split("/investigation/")[1].strip("/")
            self._handle_investigation(inv_id)
        elif path == "/history":
            self._handle_history()
        elif path == "/api/modules":
            self._json_response(engine.get_available_modules())
        elif path.startswith("/api/investigation/"):
            inv_id = path.split("/api/investigation/")[1].strip("/")
            self._handle_api_investigation(inv_id)
        elif path == "/api/history":
            self._json_response(db.list_investigations())
        elif path.startswith("/export/"):
            inv_id = path.split("/export/")[1].strip("/")
            self._handle_export(inv_id)
        else:
            self._send_error(404, "Page not found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/search":
            self._handle_search()
        elif path == "/search":
            self._handle_search_form()
        else:
            self._send_error(404, "Endpoint not found")

    def _handle_index(self):
        """Render the search landing page."""
        modules = engine.get_available_modules()
        recent = db.list_investigations(limit=10)
        template = jinja_env.get_template("index.html")
        html = template.render(
            modules=modules,
            recent_investigations=recent,
            supported_types=engine.get_supported_types(),
        )
        self._html_response(html)

    def _handle_search_form(self):
        """Handle form-based search submission."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        params = urllib.parse.parse_qs(body)

        query = params.get("query", [""])[0].strip()
        entity_type = params.get("entity_type", [None])[0]
        if entity_type == "auto":
            entity_type = None

        if not query:
            self._redirect("/")
            return

        try:
            investigation = engine.investigate(query, entity_type)
            db.save_investigation(investigation)
            self._redirect(f"/investigation/{investigation.id}")
        except Exception as e:
            logger.error(f"Search failed: {e}")
            template = jinja_env.get_template("index.html")
            html = template.render(
                error=str(e),
                modules=engine.get_available_modules(),
                recent_investigations=db.list_investigations(limit=10),
                supported_types=engine.get_supported_types(),
                query=query,
            )
            self._html_response(html)

    def _handle_search(self):
        """Handle API search (JSON)."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length).decode("utf-8"))

        query = body.get("query", "").strip()
        entity_type = body.get("entity_type")
        module_filter = body.get("modules")

        if not query:
            self._json_response({"error": "Query is required"}, status=400)
            return

        try:
            investigation = engine.investigate(query, entity_type, module_filter)
            db.save_investigation(investigation)
            summary = summarize_investigation(investigation)
            self._json_response(summary)
        except Exception as e:
            self._json_response({"error": str(e)}, status=400)

    def _handle_investigation(self, inv_id: str):
        """Render investigation results page."""
        investigation = db.load_investigation(inv_id)
        if not investigation:
            self._send_error(404, "Investigation not found")
            return

        summary = summarize_investigation(investigation)
        template = jinja_env.get_template("investigation.html")
        html = template.render(inv=summary, json_data=json.dumps(summary))
        self._html_response(html)

    def _handle_api_investigation(self, inv_id: str):
        """Return investigation data as JSON."""
        investigation = db.load_investigation(inv_id)
        if not investigation:
            self._json_response({"error": "Not found"}, status=404)
            return
        self._json_response(summarize_investigation(investigation))

    def _handle_history(self):
        """Render investigation history page."""
        investigations = db.list_investigations(limit=50)
        template = jinja_env.get_template("history.html")
        html = template.render(investigations=investigations)
        self._html_response(html)

    def _handle_export(self, inv_id: str):
        """Export investigation as HTML report."""
        investigation = db.load_investigation(inv_id)
        if not investigation:
            self._send_error(404, "Investigation not found")
            return

        summary = summarize_investigation(investigation)
        report_template_path = os.path.join(
            os.path.dirname(WEB_DIR), "reporting", "templates", "report.html"
        )
        if os.path.exists(report_template_path):
            report_env = Environment(
                loader=FileSystemLoader(os.path.dirname(report_template_path)),
                autoescape=True,
            )
            template = report_env.get_template("report.html")
        else:
            template = jinja_env.get_template("report.html")

        html = template.render(inv=summary, json_data=json.dumps(summary))
        self._html_response(html, headers={
            "Content-Disposition": f'attachment; filename="eirescope-report-{inv_id[:8]}.html"'
        })

    def _serve_static(self, filepath: str):
        """Serve static files (CSS, JS, images)."""
        full_path = os.path.join(STATIC_DIR, filepath)
        if not os.path.isfile(full_path):
            self._send_error(404, "File not found")
            return

        mime_type, _ = mimetypes.guess_type(full_path)
        mime_type = mime_type or "application/octet-stream"

        with open(full_path, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(content)

    def _html_response(self, html: str, status: int = 200, headers: dict = None):
        content = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(content)

    def _json_response(self, data, status: int = 200):
        content = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _send_error(self, code: int, message: str):
        try:
            template = jinja_env.get_template("error.html")
            html = template.render(code=code, message=message)
            self._html_response(html, status=code)
        except Exception:
            self._html_response(f"<h1>{code}</h1><p>{message}</p>", status=code)


def create_server(host: str = "0.0.0.0", port: int = 5000) -> HTTPServer:
    """Create and return the EireScope HTTP server."""
    server = HTTPServer((host, port), EireScopeHandler)
    logger.info(f"EireScope server ready at http://{host}:{port}")
    return server


def run_server(host: str = "0.0.0.0", port: int = 5000):
    """Start the EireScope web server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    server = create_server(host, port)
    print(f"""
    ╔══════════════════════════════════════════════╗
    ║           🔍 EireScope OSINT v0.1.0         ║
    ║    Open-Source Intelligence Dashboard        ║
    ╠══════════════════════════════════════════════╣
    ║  Server running at:                          ║
    ║  → http://localhost:{port}                    ║
    ║                                              ║
    ║  Press Ctrl+C to stop                        ║
    ╚══════════════════════════════════════════════╝
    """)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down EireScope...")
        server.shutdown()
