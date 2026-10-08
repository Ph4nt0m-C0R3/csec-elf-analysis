"""Polished, dependency-free PDF reports for ELF analysis results."""

from __future__ import annotations

from datetime import datetime
from io import BytesIO
from textwrap import wrap


PAGE_WIDTH = 612
PAGE_HEIGHT = 792
LEFT = 46
RIGHT = 46
CONTENT_WIDTH = PAGE_WIDTH - LEFT - RIGHT
CONTENT_TOP = 718
CONTENT_BOTTOM = 58

NAVY = (0.055, 0.122, 0.208)
BLUE = (0.067, 0.357, 0.651)
TEAL = (0.020, 0.506, 0.494)
INK = (0.102, 0.145, 0.204)
MUTED = (0.365, 0.416, 0.478)
LINE = (0.827, 0.855, 0.890)
PAPER = (0.965, 0.976, 0.988)
WHITE = (1.0, 1.0, 1.0)
GREEN = (0.067, 0.471, 0.290)
AMBER = (0.835, 0.478, 0.055)
RED = (0.745, 0.137, 0.153)
PURPLE = (0.361, 0.235, 0.612)


def build_pdf_report(result: dict) -> bytes:
    """Build a styled PDF without retaining or embedding the uploaded binary."""
    report = _ReportDocument(result)
    report.compose()
    return report.to_pdf()


class _ReportDocument:
    def __init__(self, result: dict) -> None:
        self.result = result
        self.pages: list[list[str]] = []
        self.y = CONTENT_TOP
        self._new_page()

    @property
    def commands(self) -> list[str]:
        return self.pages[-1]

    def _new_page(self) -> None:
        self.pages.append([])
        self.y = CONTENT_TOP
        self._rect(0, 738, PAGE_WIDTH, 54, NAVY)
        self._rect(0, 738, 8, 54, TEAL)
        self._text(LEFT, 768, "ELF", 15, "F2", WHITE)
        self._text(LEFT + 34, 768, "SECURITY ANALYSIS", 9, "F2", (0.72, 0.82, 0.93))
        self._text(
            PAGE_WIDTH - RIGHT,
            768,
            "BINARY SECURITY LEARNING LAB",
            7.5,
            "F1",
            (0.72, 0.82, 0.93),
            align="right",
        )

    def _ensure(self, height: float) -> None:
        if self.y - height < CONTENT_BOTTOM:
            self._new_page()

    def compose(self) -> None:
        self._cover_summary()
        self._protection_snapshot()
        self._observations()
        self._recommendations()
        self._score_details()
        self._developer_guidance()
        self._function_warnings()
        self._technical_evidence()
        self._interpretation_limit()

    def _cover_summary(self) -> None:
        result = self.result
        risk = result["risk_summary"]
        metadata = result["metadata"]
        accent = _risk_color(risk.get("security_level", "unknown"))

        self._text(LEFT, self.y, "Reverse Engineering &", 22, "F2", NAVY)
        self.y -= 27
        self._text(LEFT, self.y, "Binary Security Report", 22, "F2", NAVY)
        self.y -= 18
        self._text(LEFT, self.y, _clean(result["filename"]), 10, "F1", MUTED)
        self.y -= 30

        card_h = 92
        self._rect(LEFT, self.y - card_h, CONTENT_WIDTH, card_h, PAPER, radius=7)
        self._rect(LEFT, self.y - card_h, 7, card_h, accent, radius=7)
        self._text(LEFT + 24, self.y - 25, "ELF SECURITY SCORE", 8, "F2", MUTED)
        self._text(LEFT + 24, self.y - 58, f"{risk['score']}/100", 27, "F2", accent)
        self._text(LEFT + 151, self.y - 49, risk["rating"].upper(), 13, "F2", accent)
        self._text(LEFT + 151, self.y - 66, "Overall hardening assessment", 8, "F1", MUTED)
        self._line(LEFT + 292, self.y - 76, LEFT + 292, self.y - 17, LINE, 0.8)
        self._text(LEFT + 314, self.y - 29, "HIGHEST REVIEW PRIORITY", 7.5, "F2", MUTED)
        self._text(LEFT + 314, self.y - 51, risk["highest_label"], 14, "F2", INK)
        self._text(
            LEFT + 314,
            self.y - 68,
            f"{risk['attention_total']} item(s) need attention",
            8,
            "F1",
            MUTED,
        )
        self.y -= card_h + 20

        self._section("File overview", "Core properties identified during static inspection")
        rows = [
            ("File", result["filename"]),
            ("Size", result["file_size_display"]),
            ("Architecture", metadata.get("architecture", "Unknown")),
            ("ELF type", metadata.get("file_type", "Unknown")),
            ("Entry point", metadata.get("entry_point", "Unknown")),
            ("Analysis time", f"{result.get('elapsed_ms', 0)} ms"),
        ]
        self._key_value_grid(rows)

        generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
        report_id = str(result.get("analysis_id", "not available"))[:16]
        self._paragraph(
            f"Generated {generated} | Report ID {report_id}",
            size=7.5,
            color=MUTED,
            leading=10,
        )

    def _protection_snapshot(self) -> None:
        self._section("Protection snapshot", "Compiler, linker, and loader hardening signals")
        rows = []
        colors = []
        for key, item in self.result["protections"].items():
            label = "RPATH / RUNPATH" if key == "rpath" else key.upper()
            rows.append([label, item["status"], item["evidence"]])
            colors.append(_level_tint(item.get("level", "unknown")))
        self._table(
            ["CHECK", "STATUS", "EVIDENCE"],
            rows,
            [95, 88, CONTENT_WIDTH - 183],
            row_tints=colors,
        )

    def _observations(self) -> None:
        # Keep the section heading with at least the table header and first row.
        self._ensure(115)
        self._section("Key observations", "Prioritized findings that deserve review")
        observations = self.result["education"].get("observations", [])
        if not observations:
            self._empty_state("No notable observations were generated.")
            return
        rows, colors = [], []
        for item in observations:
            severity = item.get("severity", "info").upper()
            rows.append([severity, item.get("title", "Observation"), item.get("detail", "")])
            colors.append(_severity_tint(severity))
        self._table(
            ["LEVEL", "FINDING", "DETAIL"],
            rows,
            [57, 134, CONTENT_WIDTH - 191],
            row_tints=colors,
        )

    def _recommendations(self) -> None:
        self._section("Recommended actions", "Practical next steps, ordered by priority")
        items = self.result["education"].get("recommendations", [])
        if not items:
            self._empty_state("No additional recommendations were generated.")
            return
        for index, item in enumerate(items, start=1):
            heading = f"{index}. {item.get('priority', 'Review')} - {item.get('action', 'Review finding')}"
            self._callout(heading, item.get("reason", ""), BLUE)

    def _score_details(self) -> None:
        self._ensure(105)
        self._section("How the score is calculated", "Transparent deductions from a 100-point baseline")
        details = self.result["risk_summary"].get("score_details", {})
        factors = details.get("factors", [])
        if factors:
            rows = [
                [item.get("source", "Finding"), item.get("reason", ""), f"-{item.get('points', 0)}"]
                for item in factors
            ]
            self._table(
                ["SOURCE", "RATIONALE", "POINTS"],
                rows,
                [105, CONTENT_WIDTH - 166, 61],
            )
        else:
            self._empty_state("No score deductions were applied.")
        if details.get("capped"):
            self._callout(
                "Deduction cap applied",
                f"Raw deductions totaled {details.get('raw_deductions', 0)} points and were capped at 100.",
                AMBER,
            )
        self._paragraph(
            "The score is an educational hardening indicator. It does not prove that a binary is safe or exploitable.",
            color=MUTED,
            leading=12,
        )

    def _developer_guidance(self) -> None:
        guidance = self.result.get("developer_guidance", {})
        self._section("Developer remediation", guidance.get("summary", "Tailored build and coding guidance"))

        self._subheading("Build actions for this ELF")
        for item in guidance.get("secure_build", []):
            self._bullet(item, TEAL)
        if guidance.get("build_example"):
            self._code_box(guidance["build_example"])

        self._subheading("Coding practices to review", separated=True)
        for item in guidance.get("coding_practices", []):
            self._bullet(item, BLUE)

    def _function_warnings(self) -> None:
        self._ensure(100)
        self._section("Imported function warnings", "Imports that require careful source-level review")
        warnings = self.result["functions"].get("warnings", [])
        if not warnings:
            self._empty_state("No imported function matched the educational warning list.", GREEN)
            return
        rows, colors = [], []
        for item in warnings:
            severity = item.get("severity", "info").upper()
            rows.append([severity, f"{item.get('name', 'unknown')}()", item.get("explanation", "")])
            colors.append(_severity_tint(severity))
        self._table(
            ["LEVEL", "FUNCTION", "WHY REVIEW IT"],
            rows,
            [57, 104, CONTENT_WIDTH - 161],
            row_tints=colors,
        )

    def _technical_evidence(self) -> None:
        # Keep the section identity, first subheading, and first table together.
        self._ensure(135)
        self._section("Technical evidence", "Readelf-like structures supporting the assessment")
        self._subheading("Program headers")
        rows = []
        for item in self.result["evidence"].get("program_headers", []):
            rows.append(
                [
                    str(item.get("index", "")),
                    item.get("type", ""),
                    item.get("offset", ""),
                    item.get("virtual_address", ""),
                    item.get("flags", ""),
                ]
            )
        if rows:
            self._table(["#", "TYPE", "OFFSET", "VIRTUAL ADDRESS", "FLAGS"], rows, [30, 109, 90, 191, 100], font_size=7.5)
        else:
            self._empty_state("No program headers were available.")

        self._subheading("Dynamic entries", separated=True)
        dynamic = self.result["evidence"].get("dynamic_entries", [])
        if dynamic:
            self._table(
                ["TAG", "VALUE"],
                [[item.get("tag", ""), item.get("value", "")] for item in dynamic[:40]],
                [135, CONTENT_WIDTH - 135],
                font_size=7.5,
            )
            if len(dynamic) > 40:
                self._paragraph(f"Showing the first 40 of {len(dynamic)} dynamic entries.", size=7.5, color=MUTED)
        else:
            self._empty_state("No dynamic section entries were found.")

    def _interpretation_limit(self) -> None:
        self._section("Interpretation limit", "Use the report as evidence, not as a final verdict")
        self._callout(
            "Static analysis has limits",
            self.result["education"].get("disclaimer", "Static findings require careful interpretation."),
            PURPLE,
        )

    def _section(self, title: str, subtitle: str = "") -> None:
        self._ensure(72)
        if self.y < CONTENT_TOP - 8:
            # A divider belongs to the whitespace before the next section,
            # never behind its title or subtitle.
            self._line(LEFT, self.y - 2, PAGE_WIDTH - RIGHT, self.y - 2, LINE, 0.65)
            self.y -= 23
        self._rect(LEFT, self.y - 21, 4, 21, BLUE)
        self._text(LEFT + 13, self.y - 5, title, 14, "F2", NAVY)
        self.y -= 21
        if subtitle:
            self._text(LEFT + 13, self.y - 2, _clean(subtitle), 7.5, "F1", MUTED)
            self.y -= 15
        else:
            self.y -= 7

    def _subheading(self, title: str, *, separated: bool = False) -> None:
        self._ensure(52 if separated else 28)
        if separated and self.y < CONTENT_TOP - 8:
            self._line(LEFT, self.y - 2, PAGE_WIDTH - RIGHT, self.y - 2, LINE, 0.55)
            self.y -= 18
        self.y -= 7
        self._text(LEFT, self.y, title, 10, "F2", INK)
        self.y -= 17

    def _key_value_grid(self, rows: list[tuple[str, object]]) -> None:
        for index in range(0, len(rows), 2):
            self._ensure(39)
            row = rows[index:index + 2]
            cell_w = (CONTENT_WIDTH - 10) / 2
            for column, (label, value) in enumerate(row):
                x = LEFT + column * (cell_w + 10)
                self._rect(x, self.y - 31, cell_w, 31, WHITE, stroke=LINE, radius=4)
                self._text(x + 10, self.y - 11, _clean(label).upper(), 6.5, "F2", MUTED)
                value_text = _truncate(_clean(value), 35)
                self._text(x + 10, self.y - 24, value_text, 9, "F1", INK)
            self.y -= 39

    def _table(
        self,
        headers: list[str],
        rows: list[list[object]],
        widths: list[float],
        *,
        row_tints: list[tuple[float, float, float]] | None = None,
        font_size: float = 8,
    ) -> None:
        header_h = 25
        self._ensure(header_h + 22)
        self._table_header(headers, widths, header_h)
        for row_index, row in enumerate(rows):
            wrapped = [
                _wrap_text(_clean(value), max(10, widths[i] - 14), font_size)
                for i, value in enumerate(row)
            ]
            row_h = max(25, max(len(lines) for lines in wrapped) * (font_size + 3) + 12)
            if self.y - row_h < CONTENT_BOTTOM:
                self._new_page()
                self._table_header(headers, widths, header_h)
            tint = row_tints[row_index] if row_tints else (WHITE if row_index % 2 == 0 else PAPER)
            self._rect(LEFT, self.y - row_h, sum(widths), row_h, tint, stroke=LINE)
            x = LEFT
            for cell_index, lines in enumerate(wrapped):
                if cell_index:
                    self._line(x, self.y, x, self.y - row_h, LINE, 0.45)
                font = "F2" if cell_index == 0 else "F1"
                for line_index, line in enumerate(lines):
                    self._text(x + 7, self.y - 14 - line_index * (font_size + 3), line, font_size, font, INK)
                x += widths[cell_index]
            self.y -= row_h
        self.y -= 5

    def _table_header(self, headers: list[str], widths: list[float], height: float) -> None:
        self._rect(LEFT, self.y - height, sum(widths), height, NAVY)
        x = LEFT
        for index, header in enumerate(headers):
            self._text(x + 7, self.y - 16, header, 7, "F2", WHITE)
            x += widths[index]
        self.y -= height

    def _callout(self, title: str, body: str, accent: tuple[float, float, float]) -> None:
        body_lines = _wrap_text(_clean(body), CONTENT_WIDTH - 38, 8.5)
        title_lines = _wrap_text(_clean(title), CONTENT_WIDTH - 38, 9.5)
        height = 17 + len(title_lines) * 12 + len(body_lines) * 11 + 9
        self._ensure(height + 7)
        self._rect(LEFT, self.y - height, CONTENT_WIDTH, height, PAPER, stroke=LINE, radius=4)
        self._rect(LEFT, self.y - height, 5, height, accent, radius=4)
        offset = 17
        for line in title_lines:
            self._text(LEFT + 17, self.y - offset, line, 9.5, "F2", INK)
            offset += 12
        for line in body_lines:
            self._text(LEFT + 17, self.y - offset, line, 8.5, "F1", MUTED)
            offset += 11
        self.y -= height + 7

    def _code_box(self, text: str) -> None:
        lines = _wrap_text(_clean(text), CONTENT_WIDTH - 28, 7.5, factor=0.60)
        height = len(lines) * 10 + 30
        self._ensure(height + 7)
        self._rect(LEFT, self.y - height, CONTENT_WIDTH, height, NAVY, radius=4)
        self._text(LEFT + 12, self.y - 13, "BUILD EXAMPLE", 6.5, "F2", (0.55, 0.75, 0.91))
        for index, line in enumerate(lines):
            self._text(LEFT + 12, self.y - 28 - index * 10, line, 7.5, "F3", WHITE)
        self.y -= height + 7

    def _bullet(self, text: str, color: tuple[float, float, float]) -> None:
        lines = _wrap_text(_clean(text), CONTENT_WIDTH - 27, 8.5)
        height = max(15, len(lines) * 11 + 4)
        self._ensure(height)
        self._rect(LEFT + 1, self.y - 10, 5, 5, color, radius=2)
        for index, line in enumerate(lines):
            self._text(LEFT + 17, self.y - 10 - index * 11, line, 8.5, "F1", INK)
        self.y -= height

    def _paragraph(self, text: str, *, size: float = 8.5, color=INK, leading: float = 11) -> None:
        lines = _wrap_text(_clean(text), CONTENT_WIDTH, size)
        self._ensure(len(lines) * leading + 4)
        for line in lines:
            self._text(LEFT, self.y - size, line, size, "F1", color)
            self.y -= leading
        self.y -= 4

    def _empty_state(self, text: str, accent=TEAL) -> None:
        self._callout("No flagged items", text, accent)

    def _text(self, x: float, y: float, text: str, size: float, font: str, color, *, align: str = "left") -> None:
        safe = _pdf_escape(_clean(text))
        if align == "right":
            x -= _estimated_width(_clean(text), size, 0.53 if font == "F1" else 0.57)
        r, g, b = color
        self.commands.append(
            f"BT /{font} {_number(size)} Tf {_number(r)} {_number(g)} {_number(b)} rg "
            f"1 0 0 1 {_number(x)} {_number(y)} Tm ({safe}) Tj ET"
        )

    def _rect(self, x, y, width, height, fill, *, stroke=None, radius=0) -> None:
        r, g, b = fill
        commands = ["q", f"{_number(r)} {_number(g)} {_number(b)} rg"]
        if stroke:
            sr, sg, sb = stroke
            commands.append(f"{_number(sr)} {_number(sg)} {_number(sb)} RG 0.55 w")
        operator = "B" if stroke else "f"
        commands.append(f"{_number(x)} {_number(y)} {_number(width)} {_number(height)} re {operator}")
        commands.append("Q")
        self.commands.extend(commands)

    def _line(self, x1, y1, x2, y2, color, width) -> None:
        r, g, b = color
        self.commands.append(
            f"q {_number(r)} {_number(g)} {_number(b)} RG {_number(width)} w "
            f"{_number(x1)} {_number(y1)} m {_number(x2)} {_number(y2)} l S Q"
        )

    def to_pdf(self) -> bytes:
        total = len(self.pages)
        for page_no, commands in enumerate(self.pages, start=1):
            commands.append(f"q {_number(LINE[0])} {_number(LINE[1])} {_number(LINE[2])} RG 0.6 w {LEFT} 43 m {PAGE_WIDTH - RIGHT} 43 l S Q")
            footer = "Educational static analysis - uploaded binaries are not embedded in this report"
            commands.append(_text_command(LEFT, 28, footer, 6.5, "F1", MUTED))
            commands.append(_text_command(PAGE_WIDTH - RIGHT, 28, f"PAGE {page_no} OF {total}", 6.5, "F2", MUTED, align="right"))
        return _write_pdf(self.pages, self.result)


def _write_pdf(pages: list[list[str]], result: dict) -> bytes:
    page_count = len(pages)
    font_regular = 3 + page_count * 2
    font_bold = font_regular + 1
    font_mono = font_regular + 2
    info_obj = font_regular + 3
    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: (
            f"<< /Type /Pages /Kids [{' '.join(f'{3 + i * 2} 0 R' for i in range(page_count))}] "
            f"/Count {page_count} >>"
        ).encode("latin-1"),
        font_regular: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        font_bold: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        font_mono: b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
    }
    for index, commands in enumerate(pages):
        page_obj = 3 + index * 2
        content_obj = page_obj + 1
        stream = "\n".join(commands).encode("latin-1", errors="replace")
        objects[page_obj] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 {font_regular} 0 R /F2 {font_bold} 0 R /F3 {font_mono} 0 R >> >> "
            f"/Contents {content_obj} 0 R >>"
        ).encode("latin-1")
        objects[content_obj] = f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream"

    title = _pdf_escape(f"ELF Security Analysis - {_clean(result.get('filename', 'binary'))}")
    objects[info_obj] = f"<< /Title ({title}) /Author (Binary Security Learning Lab) /Subject (Static ELF security analysis) >>".encode("latin-1")

    output = BytesIO()
    output.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number in range(1, info_obj + 1):
        offsets.append(output.tell())
        output.write(f"{number} 0 obj\n".encode("ascii"))
        output.write(objects[number])
        output.write(b"\nendobj\n")
    xref = output.tell()
    output.write(f"xref\n0 {info_obj + 1}\n".encode("ascii"))
    output.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.write(
        (
            f"trailer\n<< /Size {info_obj + 1} /Root 1 0 R /Info {info_obj} 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n"
        ).encode("ascii")
    )
    return output.getvalue()


def _text_command(x, y, text, size, font, color, *, align="left") -> str:
    clean = _clean(text)
    if align == "right":
        x -= _estimated_width(clean, size, 0.53 if font == "F1" else 0.57)
    r, g, b = color
    return (
        f"BT /{font} {_number(size)} Tf {_number(r)} {_number(g)} {_number(b)} rg "
        f"1 0 0 1 {_number(x)} {_number(y)} Tm ({_pdf_escape(clean)}) Tj ET"
    )


def _clean(value: object) -> str:
    return str(value if value is not None else "").replace("\u2011", "-").replace("\u2013", "-").replace("\u2014", "-")


def _wrap_text(text: str, width: float, size: float, *, factor: float = 0.53) -> list[str]:
    maximum = max(8, int(width / max(1, size * factor)))
    paragraphs = text.splitlines() or [""]
    lines: list[str] = []
    for paragraph in paragraphs:
        lines.extend(wrap(paragraph, width=maximum, break_long_words=True, break_on_hyphens=True) or [""])
    return lines


def _truncate(text: str, length: int) -> str:
    return text if len(text) <= length else text[: max(0, length - 3)] + "..."


def _estimated_width(text: str, size: float, factor: float) -> float:
    return len(text) * size * factor


def _number(value: float) -> str:
    return f"{value:.3f}".rstrip("0").rstrip(".")


def _pdf_escape(text: str) -> str:
    value = text.encode("latin-1", errors="replace").decode("latin-1")
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _risk_color(level: str):
    return {"good": GREEN, "low": TEAL, "medium": AMBER, "high": RED}.get(level, MUTED)


def _level_tint(level: str):
    return {
        "good": (0.918, 0.973, 0.941),
        "warn": (1.0, 0.969, 0.875),
        "danger": (1.0, 0.925, 0.929),
        "unknown": (0.947, 0.953, 0.961),
    }.get(level, WHITE)


def _severity_tint(severity: str):
    return {
        "CRITICAL": (0.992, 0.886, 0.894),
        "HIGH": (1.0, 0.925, 0.929),
        "MEDIUM": (1.0, 0.969, 0.875),
        "LOW": (0.918, 0.973, 0.941),
        "INFO": (0.925, 0.957, 0.992),
    }.get(severity, PAPER)
