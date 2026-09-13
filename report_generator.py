import io
import datetime
from xml.sax.saxutils import escape as xml_escape
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors


def sanitize_text(text: str) -> str:
    """Sanitize text for ReportLab XML flowables (escapes &, <, > and strips emojis)."""
    if not text:
        return ""
    # Strip emojis that standard PDF fonts cannot render
    clean = ""
    for char in str(text):
        if ord(char) < 0x2000 or ord(char) > 0x2BFF:
            clean += char
        else:
            clean += " "
    return xml_escape(clean.strip())


def generate_pdf_report(data: dict) -> bytes:
    """
    Generates a professional, print-ready PDF security audit report.
    Returns the raw PDF file bytes.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        alignment=2,  # Right aligned
    )
    meta_label_style = ParagraphStyle(
        "MetaLabel",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#64748b"),
    )
    meta_val_style = ParagraphStyle(
        "MetaVal",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
    )
    score_style = ParagraphStyle(
        "ScoreStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=26,
        leading=30,
        alignment=1,  # Center aligned
    )
    grade_style = ParagraphStyle(
        "GradeStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        alignment=1,  # Center aligned
        textColor=colors.white,
    )
    section_head_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
    )
    check_name_style = ParagraphStyle(
        "CheckName",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#0f172a"),
    )
    check_cat_style = ParagraphStyle(
        "CheckCat",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#64748b"),
    )
    check_pass_style = ParagraphStyle(
        "CheckPass",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        alignment=2,
        textColor=colors.HexColor("#15803d"),
    )
    check_fail_style = ParagraphStyle(
        "CheckFail",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        alignment=2,
        textColor=colors.HexColor("#b91c1c"),
    )
    check_exp_style = ParagraphStyle(
        "CheckExplanation",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    footer_style = ParagraphStyle(
        "ReportFooter",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#94a3b8"),
        alignment=1,
    )

    elements = []

    # 1. Header Bar
    header_table = Table(
        [
            [
                Paragraph("SecureScan <b>Audit Report</b>", title_style),
                Paragraph("Automated 10-Point Security Evaluation<br/>Generated: " + sanitize_text(data.get("timestamp", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))), subtitle_style),
            ]
        ],
        colWidths=[320, 220],
    )
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(header_table)
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=12))

    # 2. Executive Summary Block
    score = int(data.get("score", 0))
    grade = str(data.get("grade", "F")).upper()

    if score >= 90:
        score_color = colors.HexColor("#15803d")
        badge_bg = colors.HexColor("#15803d")
    elif score >= 80:
        score_color = colors.HexColor("#0369a1")
        badge_bg = colors.HexColor("#0369a1")
    elif score >= 65:
        score_color = colors.HexColor("#b45309")
        badge_bg = colors.HexColor("#b45309")
    else:
        score_color = colors.HexColor("#b91c1c")
        badge_bg = colors.HexColor("#b91c1c")

    score_style.textColor = score_color

    meta_content = [
        [
            Paragraph("Target URL:", meta_label_style),
            Paragraph(sanitize_text(data.get("url", "N/A")), meta_val_style),
        ],
        [
            Paragraph("Final Scanned URL:", meta_label_style),
            Paragraph(sanitize_text(data.get("final_url", data.get("url", "N/A"))), meta_val_style),
        ],
        [
            Paragraph("Audit Scope:", meta_label_style),
            Paragraph("10 Technical Cybersecurity Vectors", meta_val_style),
        ],
    ]
    meta_table = Table(meta_content, colWidths=[110, 270])
    meta_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))

    score_card = Table(
        [
            [Paragraph(f"{score} / 100", score_style)],
            [Paragraph(f"GRADE {grade}", grade_style)],
        ],
        colWidths=[140],
    )
    score_card.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 1), (0, 1), badge_bg),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))

    summary_table = Table(
        [[meta_table, score_card]],
        colWidths=[390, 150],
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 16))

    # 3. Checks List
    elements.append(Paragraph("Security Assessment Findings (10 Checks Evaluated)", section_head_style))
    elements.append(Spacer(1, 8))

    checks = data.get("checks", [])
    for idx, c in enumerate(checks, 1):
        c_name = sanitize_text(c.get("name", f"Check {idx}"))
        c_cat = sanitize_text(c.get("category", "General Security"))
        c_passed = bool(c.get("passed", False))
        c_deducted = int(c.get("deducted", 0))
        c_exp = sanitize_text(c.get("explanation", "No detailed findings."))

        if c_passed:
            status_text = "[PASSED] 0 pts deducted"
            status_style = check_pass_style
            card_border = colors.HexColor("#bbf7d0")
            card_bg = colors.HexColor("#f0fdf4")
        else:
            status_text = f"[FAILED] -{c_deducted} pts deducted"
            status_style = check_fail_style
            card_border = colors.HexColor("#fecaca")
            card_bg = colors.HexColor("#fef2f2")

        header_row = Table(
            [
                [
                    Paragraph(f"<b>{idx}. {c_name}</b> <font color='#64748b' size='8'>({c_cat})</font>", check_name_style),
                    Paragraph(f"<b>{status_text}</b>", status_style),
                ]
            ],
            colWidths=[380, 140],
        )
        header_row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))

        check_box = Table(
            [
                [header_row],
                [Paragraph(c_exp, check_exp_style)],
            ],
            colWidths=[520],
        )
        check_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), card_bg),
            ("BOX", (0, 0), (-1, -1), 0.75, card_border),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))

        elements.append(KeepTogether([check_box, Spacer(1, 6)]))

    # 4. Footer Note
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=8))
    elements.append(Paragraph(
        "Report generated by SecureScan Security Auditor · https://project-secure-scan-20.vercel.app · For technical security analysis only.",
        footer_style
    ))

    doc.build(elements)
    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes
