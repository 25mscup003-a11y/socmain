"""Build the offline viewer: python3 scripts/generate_workflow_html.py.

Requires Python-Markdown (python3 -m pip install Markdown).
"""

from html import escape
from pathlib import Path
import re

import markdown


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "workflow.md"
ASSETS = ROOT / "docs" / "workflow-viewer"


def render(text):
    html = markdown.markdown(text, extensions=["tables", "fenced_code", "sane_lists", "nl2br"])
    return html.replace("<table>", '<div class="table-scroll" tabindex="0"><table>').replace(
        "</table>", "</table></div>"
    )


def build():
    source = SOURCE.read_text(encoding="utf-8")
    chunks = re.split(r"^## (\d+)\. (.+)$", source, flags=re.MULTILINE)
    sections = []
    navigation = []
    bodies = {}
    for offset in range(1, len(chunks), 3):
        number, title, body = chunks[offset : offset + 3]
        bodies[int(number)] = body
        navigation.append(
            f'<a href="#guide-{number}" data-guide="{number}"><span>{int(number):02}</span>{escape(title)}</a>'
        )
        sections.append(
            f'<section class="guide-section" id="guide-{number}" tabindex="-1">'
            f'<p class="eyebrow">SECTION {int(number):02}</p>'
            f'<h2>{escape(title)}</h2>{render(body)}</section>'
        )

    template = (ASSETS / "template.html").read_text(encoding="utf-8")
    replacements = {
        "__VIEWER_CSS__": (ASSETS / "viewer.css").read_text(encoding="utf-8"),
        "__VIEWER_JS__": (ASSETS / "viewer.js").read_text(encoding="utf-8"),
        "__GUIDE_INTRO__": render(chunks[0]),
        "__GUIDE_SECTIONS__": "\n".join(sections),
        "__GUIDE_NAV__": "\n".join(navigation),
        "__ACCESS_TABLES__": render(bodies[9]),
        "__ENCRYPTION_TABLE__": render(bodies[19].split("### Encrypted data")[0]),
    }
    # One substitution pass keeps source content from being treated as template tokens.
    output = re.sub(r"__(?:VIEWER_CSS|VIEWER_JS|GUIDE_INTRO|GUIDE_SECTIONS|GUIDE_NAV|ACCESS_TABLES|ENCRYPTION_TABLE)__",
                    lambda match: replacements[match.group()], template)
    destination = ROOT / "workflow.html"
    destination.write_text(output, encoding="utf-8")
    print(f"Built {destination.name}: {len(sections)} guide sections, {destination.stat().st_size:,} bytes")


if __name__ == "__main__":
    build()
