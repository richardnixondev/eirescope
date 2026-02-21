"""Report generator — Creates exportable HTML investigation reports."""
import os
import json
import logging
from jinja2 import Environment, FileSystemLoader
from eirescope.core.entity import Investigation
from eirescope.core.results import summarize_investigation

logger = logging.getLogger("eirescope.reporting")

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
WEB_TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "web", "templates"
)


class ReportGenerator:
    """Generates HTML investigation reports."""

    def __init__(self):
        # Try reporting templates first, fall back to web templates
        dirs = [d for d in [TEMPLATE_DIR, WEB_TEMPLATE_DIR] if os.path.isdir(d)]
        self.env = Environment(
            loader=FileSystemLoader(dirs),
            autoescape=True,
        )

    def generate_html(self, investigation: Investigation) -> str:
        """Generate a standalone HTML report."""
        summary = summarize_investigation(investigation)
        template = self.env.get_template("report.html")
        return template.render(inv=summary, json_data=json.dumps(summary))

    def save_html(self, investigation: Investigation, output_path: str) -> str:
        """Generate and save HTML report to file."""
        html = self.generate_html(investigation)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"Report saved to {output_path}")
        return output_path
