"""Build the editable AJNAT SOC DOCX from the evidence-based Markdown source."""

from pathlib import Path
import re

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Mm, Pt, RGBColor


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "AJNAT_SOC_Complete_Product_Technical_Report.md"
OUTPUT = ROOT / "AJNAT_SOC_Complete_Product_Technical_Report.docx"


def set_cell_shading(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def add_page_number(paragraph):
    paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = paragraph.add_run("Page ")
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = " PAGE "
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.append(begin)
    run._r.append(instr)
    run._r.append(end)


def add_inline(paragraph, text):
    """Add minimal Markdown bold/italic/code formatting to a paragraph."""
    token = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)")
    pos = 0
    for match in token.finditer(text):
        if match.start() > pos:
            paragraph.add_run(text[pos:match.start()])
        value = match.group(0)
        if value.startswith("**"):
            run = paragraph.add_run(value[2:-2])
            run.bold = True
        elif value.startswith("`"):
            run = paragraph.add_run(value[1:-1])
            run.font.name = "DejaVu Sans Mono"
            run.font.size = Pt(9)
        else:
            run = paragraph.add_run(value[1:-1])
            run.italic = True
        pos = match.end()
    if pos < len(text):
        paragraph.add_run(text[pos:])


def configure_document(doc):
    section = doc.sections[0]
    section.page_height = Mm(297)
    section.page_width = Mm(210)
    section.top_margin = Mm(20)
    section.bottom_margin = Mm(20)
    section.left_margin = Mm(18)
    section.right_margin = Mm(18)

    normal = doc.styles["Normal"]
    normal.font.name = "Liberation Sans"
    normal.font.size = Pt(11)
    normal.paragraph_format.space_after = Pt(7)
    normal.paragraph_format.line_spacing = 1.24

    colors = {1: "0B3A67", 2: "14558C", 3: "264B6B", 4: "334155"}
    sizes = {1: 22, 2: 16, 3: 12, 4: 11}
    for level in range(1, 5):
        style = doc.styles[f"Heading {level}"]
        style.font.name = "Liberation Sans"
        style.font.size = Pt(sizes[level])
        style.font.color.rgb = RGBColor.from_string(colors[level])
        style.font.bold = True
        style.paragraph_format.space_before = Pt(12 if level > 1 else 4)
        style.paragraph_format.space_after = Pt(6)
        style.paragraph_format.keep_with_next = True

    if "Caption AJNAT" not in [s.name for s in doc.styles]:
        style = doc.styles.add_style("Caption AJNAT", WD_STYLE_TYPE.PARAGRAPH)
        style.font.name = "Liberation Sans"
        style.font.size = Pt(8.5)
        style.font.italic = True
        style.font.color.rgb = RGBColor(71, 85, 105)
        style.paragraph_format.space_after = Pt(8)
        style.paragraph_format.keep_with_next = False

    footer = section.footer.paragraphs[0]
    footer.add_run("AJNAT SOC — Confidential & Proprietary                         ")
    footer.style = doc.styles["Footer"]
    add_page_number(footer)


def parse_table(lines, start):
    rows = []
    i = start
    while i < len(lines) and lines[i].strip().startswith("|"):
        rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
        i += 1
    if len(rows) >= 2 and all(re.fullmatch(r":?-{3,}:?", c.replace(" ", "")) for c in rows[1]):
        del rows[1]
    return rows, i


def add_table(doc, rows):
    if not rows:
        return
    cols = max(len(r) for r in rows)
    table = doc.add_table(rows=len(rows), cols=cols)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for r_idx, row in enumerate(rows):
        for c_idx in range(cols):
            cell = table.cell(r_idx, c_idx)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP
            cell.text = ""
            p = cell.paragraphs[0]
            add_inline(p, row[c_idx] if c_idx < len(row) else "")
            for run in p.runs:
                run.font.size = Pt(8.3)
                if r_idx == 0:
                    run.bold = True
                    run.font.color.rgb = RGBColor(255, 255, 255)
            if r_idx == 0:
                set_cell_shading(cell, "0B3A67")
            elif r_idx % 2 == 0:
                set_cell_shading(cell, "F2F7FB")
    doc.add_paragraph()


def add_cover(doc, lines):
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.paragraph_format.space_before = Pt(85)
    run = title.add_run(lines[0].lstrip("# "))
    run.bold = True
    run.font.size = Pt(28)
    run.font.color.rgb = RGBColor(7, 57, 99)

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = sub.add_run(lines[2].lstrip("# "))
    run.bold = True
    run.font.size = Pt(18)
    run.font.color.rgb = RGBColor(31, 115, 183)

    for line in lines[4:10]:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        add_inline(p, line.rstrip("  "))
    badge = doc.add_paragraph()
    badge.alignment = WD_ALIGN_PARAGRAPH.CENTER
    badge.paragraph_format.space_before = Pt(24)
    run = badge.add_run("CONFIDENTIAL & PROPRIETARY")
    run.bold = True
    run.font.color.rgb = RGBColor(160, 39, 39)
    doc.add_page_break()


def build():
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    doc = Document()
    configure_document(doc)
    add_cover(doc, lines)

    # Cover occupies the initial source lines. Continue after its horizontal rule.
    i = next(idx for idx, line in enumerate(lines) if line.strip() == "---") + 1
    pending = []
    frontmatter = True

    def flush():
        nonlocal pending
        if pending:
            text = " ".join(x.strip() for x in pending).strip()
            if text:
                p = doc.add_paragraph()
                add_inline(p, text)
                if frontmatter:
                    p.paragraph_format.line_spacing = 1.0
                    p.paragraph_format.space_after = Pt(4)
                    for run in p.runs:
                        run.font.size = Pt(9)
            pending = []

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped == '<div class="page-break"></div>':
            flush()
            doc.add_page_break()
            frontmatter = False
            i += 1
            continue
        if stripped.startswith("|"):
            flush()
            rows, i = parse_table(lines, i)
            add_table(doc, rows)
            continue
        image_match = re.fullmatch(r"!\[([^]]*)\]\(([^)]+)\)", stripped)
        if image_match:
            flush()
            path = ROOT / image_match.group(2)
            if path.exists():
                p = doc.add_paragraph()
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p.add_run().add_picture(str(path), width=Inches(6.6))
            i += 1
            continue
        heading = re.match(r"^(#{1,4})\s+(.+)$", stripped)
        if heading:
            flush()
            p = doc.add_heading(heading.group(2), level=len(heading.group(1)))
            if frontmatter:
                for run in p.runs:
                    run.font.size = Pt(14 if len(heading.group(1)) == 2 else 10.5)
            i += 1
            continue
        if stripped == "---":
            flush()
            i += 1
            continue
        if stripped.startswith(">"):
            flush()
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Mm(6)
            add_inline(p, stripped.lstrip("> "))
            i += 1
            continue
        bullet = re.match(r"^[-*]\s+(.+)$", stripped)
        number = re.match(r"^\d+\.\s+(.+)$", stripped)
        if bullet or number:
            flush()
            p = doc.add_paragraph(style="List Bullet" if bullet else "List Number")
            add_inline(p, (bullet or number).group(1))
            i += 1
            continue
        if not stripped:
            flush()
        else:
            pending.append(stripped.rstrip("  "))
        i += 1
    flush()

    # Avoid accidental extra blank first paragraph in otherwise intentional pages.
    props = doc.core_properties
    props.title = "AI-Powered Threat Detection and Incident Response (SOC) Platform"
    props.subject = "AJNAT SOC Product & Technical Documentation"
    props.author = "AJNAT Product, Engineering and Information Security"
    props.comments = "Confidential and Proprietary"
    doc.save(OUTPUT)
    print(f"Wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes)")


if __name__ == "__main__":
    build()
