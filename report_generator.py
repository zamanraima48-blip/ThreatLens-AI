from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from datetime import datetime
from collections import Counter, defaultdict
import os
import html


# =========================================================
# HELPERS
# =========================================================

def _safe(value):
    if value is None:
        return "N/A"
    return str(value)


def _text(value):
    """Convert arbitrary values into safe ReportLab text."""
    return html.escape(_safe(value))


def _flatten_iocs(iocs):
    rows = []

    if isinstance(iocs, dict):
        for category, values in iocs.items():

            if isinstance(values, (list, tuple, set)):
                for value in values:
                    rows.append([
                        _safe(category),
                        _safe(value)
                    ])

            elif values:
                rows.append([
                    _safe(category),
                    _safe(values)
                ])

    elif isinstance(iocs, list):
        for item in iocs:

            if isinstance(item, dict):
                rows.append([
                    _safe(item.get("type", "IOC")),
                    _safe(item.get("value", item))
                ])

            else:
                rows.append([
                    "IOC",
                    _safe(item)
                ])

    return rows


def _threat_evidence(threat):
    return threat.get(
        "log",
        threat.get(
            "message",
            threat.get(
                "evidence",
                "Security event detected"
            )
        )
    )


def _severity_rank(severity):
    ranking = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0
    }

    return ranking.get(
        str(severity).strip().lower(),
        0
    )


def _highest_severity(values):
    if not values:
        return "N/A"

    return max(
        values,
        key=_severity_rank
    )


def _aggregate_threats(threats):
    """
    Aggregate threats by threat type.

    This prevents thousands of individual rows
    from being inserted into the PDF.
    """

    grouped = defaultdict(list)

    for threat in threats:

        if not isinstance(threat, dict):
            continue

        threat_type = _safe(
            threat.get(
                "type",
                "Unknown Threat"
            )
        )

        grouped[threat_type].append(threat)

    summary = []

    for threat_type, items in grouped.items():

        severities = [
            item.get("severity", "Medium")
            for item in items
        ]

        representative = max(
            items,
            key=lambda item: _severity_rank(
                item.get("severity", "Medium")
            )
        )

        summary.append({
            "type": threat_type,
            "count": len(items),
            "severity": _highest_severity(severities),
            "evidence": _threat_evidence(representative)
        })

    summary.sort(
        key=lambda item: (
            _severity_rank(item["severity"]),
            item["count"]
        ),
        reverse=True
    )

    return summary


def _unique_mitre(mitre):
    unique = {}

    for item in mitre:

        if not isinstance(item, dict):
            continue

        technique_id = _safe(
            item.get(
                "Technique ID",
                "N/A"
            )
        )

        technique = _safe(
            item.get(
                "Technique",
                "N/A"
            )
        )

        tactic = _safe(
            item.get(
                "Tactic",
                "N/A"
            )
        )

        key = (
            technique_id,
            technique,
            tactic
        )

        unique[key] = {
            "Technique ID": technique_id,
            "Technique": technique,
            "Tactic": tactic
        }

    return list(unique.values())


def _unique_iocs(rows):
    seen = set()
    unique = []

    for row in rows:

        if len(row) < 2:
            continue

        key = (
            str(row[0]).strip().lower(),
            str(row[1]).strip().lower()
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(row)

    return unique


def _footer(canvas, doc):
    canvas.saveState()

    canvas.setFont(
        "Helvetica",
        8
    )

    canvas.setFillColor(
        colors.grey
    )

    canvas.drawString(
        20 * mm,
        12 * mm,
        "ThreatLens AI • AI Security Incident Investigation"
    )

    canvas.drawRightString(
        190 * mm,
        12 * mm,
        f"Page {doc.page}"
    )

    canvas.restoreState()


# =========================================================
# MAIN REPORT GENERATOR
# =========================================================

def generate_report(data, output_path):

    os.makedirs(
        os.path.dirname(output_path),
        exist_ok=True
    )

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=25,
        leading=30,
        alignment=TA_CENTER,
        spaceAfter=12
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=13,
        leading=18,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#555555"),
        spaceAfter=20
    )

    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontSize=16,
        leading=20,
        spaceBefore=10,
        spaceAfter=10
    )

    subsection_style = ParagraphStyle(
        "Subsection",
        parent=styles["Heading3"],
        fontSize=11,
        leading=14,
        spaceBefore=7,
        spaceAfter=5
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=14,
        spaceAfter=6
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11
    )

    story = []

    # =====================================================
    # PREPARE DATA
    # =====================================================

    threats = data.get(
        "threats",
        []
    )

    if not isinstance(threats, list):
        threats = []

    threat_summary = _aggregate_threats(
        threats
    )

    ioc_rows = _flatten_iocs(
        data.get(
            "iocs",
            []
        )
    )

    ioc_rows = _unique_iocs(
        ioc_rows
    )

    mitre = data.get(
        "mitre_mapping",
        []
    )

    if not isinstance(mitre, list):
        mitre = []

    mitre = _unique_mitre(
        mitre
    )

    # =====================================================
    # COVER PAGE
    # =====================================================

    story.append(
        Spacer(
            1,
            35 * mm
        )
    )

    story.append(
        Paragraph(
            "ThreatLens AI",
            title_style
        )
    )

    story.append(
        Paragraph(
            "AI Security Incident Investigation Report",
            subtitle_style
        )
    )

    story.append(
        Spacer(
            1,
            15 * mm
        )
    )

    cover_data = [
        [
            "Analysis Mode",
            _text(
                data.get(
                    "analysis_mode",
                    "Security Log Analysis"
                )
            )
        ],
        [
            "Source",
            _text(
                data.get(
                    "filename",
                    data.get(
                        "source",
                        "Live System Journal Scan"
                    )
                )
            )
        ],
        [
            "Generated",
            datetime.now().strftime(
                "%d %B %Y, %H:%M:%S"
            )
        ],
        [
            "Threat Classification",
            _text(
                data.get(
                    "threat_classification",
                    "N/A"
                )
            )
        ],
        [
            "Severity",
            _text(
                data.get(
                    "severity",
                    "Low"
                )
            )
        ],
        [
            "Risk Score",
            _text(
                data.get(
                    "risk_score",
                    0
                )
            )
        ]
    ]

    cover_table = Table(
        cover_data,
        colWidths=[
            55 * mm,
            105 * mm
        ]
    )

    cover_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#eeeeee")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "FONTNAME",
                (1, 0),
                (1, -1),
                "Helvetica"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(
        cover_table
    )

    story.append(
        Spacer(
            1,
            20 * mm
        )
    )

    story.append(
        Paragraph(
            "CONFIDENTIAL SECURITY ANALYSIS",
            ParagraphStyle(
                "Confidential",
                parent=body_style,
                alignment=TA_CENTER,
                fontName="Helvetica-Bold"
            )
        )
    )

    story.append(
        PageBreak()
    )

    # =====================================================
    # EXECUTIVE SUMMARY
    # =====================================================

    story.append(
        Paragraph(
            "1. Executive Summary",
            section_style
        )
    )

    story.append(
        Paragraph(
            _text(
                data.get(
                    "executive_summary",
                    "No executive summary is available."
                )
            ),
            body_style
        )
    )

    summary_table = Table(
        [
            [
                "Key Finding",
                "Value"
            ],
            [
                "Logs Analyzed",
                _text(
                    data.get(
                        "total_lines",
                        0
                    )
                )
            ],
            [
                "Threat Events",
                _text(
                    data.get(
                        "total_threats",
                        len(threats)
                    )
                )
            ],
            [
                "Unique Threat Types",
                str(
                    len(threat_summary)
                )
            ],
            [
                "Unique IOCs",
                str(
                    len(ioc_rows)
                )
            ],
            [
                "MITRE Techniques",
                str(
                    len(mitre)
                )
            ],
            [
                "Overall Severity",
                _text(
                    data.get(
                        "severity",
                        "Low"
                    )
                )
            ],
            [
                "Risk Score",
                _text(
                    data.get(
                        "risk_score",
                        0
                    )
                )
            ]
        ],
        colWidths=[
            90 * mm,
            70 * mm
        ],
        repeatRows=1
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#222222")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.grey
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#f5f5f5")
                ]
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(
        summary_table
    )

    # =====================================================
    # THREAT ANALYSIS
    # =====================================================

    story.append(
        Paragraph(
            "2. Threat Analysis",
            section_style
        )
    )

    if threat_summary:

        story.append(
            Paragraph(
                "Threat events are aggregated by threat type. "
                "Individual log entries are not reproduced in full "
                "to keep the investigation report concise.",
                body_style
            )
        )

        threat_rows = [
            [
                "Threat Type",
                "Events",
                "Highest Severity"
            ]
        ]

        for item in threat_summary:

            threat_rows.append([
                Paragraph(
                    _text(item["type"]),
                    small_style
                ),
                str(
                    item["count"]
                ),
                _text(
                    item["severity"]
                )
            ])

        threat_table = Table(
            threat_rows,
            colWidths=[
                90 * mm,
                30 * mm,
                40 * mm
            ],
            repeatRows=1
        )

        threat_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#222222")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor("#f7f7f7")
                    ]
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                )
            ])
        )

        story.append(
            threat_table
        )

    else:

        story.append(
            Paragraph(
                "No threats were detected in the analyzed data.",
                body_style
            )
        )

    # =====================================================
    # PRIORITY INCIDENTS
    # =====================================================

    story.append(
        Paragraph(
            "3. Priority Security Events",
            section_style
        )
    )

    priority_threats = sorted(
        [
            threat
            for threat in threats
            if isinstance(threat, dict)
        ],
        key=lambda threat: _severity_rank(
            threat.get(
                "severity",
                "Medium"
            )
        ),
        reverse=True
    )

    # Maximum 10 representative events.
    priority_threats = priority_threats[:10]

    if priority_threats:

        evidence_rows = [
            [
                "#",
                "Threat",
                "Severity",
                "Representative Evidence"
            ]
        ]

        for index, threat in enumerate(
            priority_threats,
            1
        ):

            evidence_rows.append([
                str(index),
                Paragraph(
                    _text(
                        threat.get(
                            "type",
                            "Unknown Threat"
                        )
                    ),
                    small_style
                ),
                _text(
                    threat.get(
                        "severity",
                        "Medium"
                    )
                ),
                Paragraph(
                    _text(
                        _threat_evidence(threat)
                    ),
                    small_style
                )
            ])

        evidence_table = Table(
            evidence_rows,
            colWidths=[
                8 * mm,
                38 * mm,
                25 * mm,
                89 * mm
            ],
            repeatRows=1
        )

        evidence_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#222222")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7.5
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor("#f7f7f7")
                    ]
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                )
            ])
        )

        story.append(
            evidence_table
        )

    else:

        story.append(
            Paragraph(
                "No priority security events were available.",
                body_style
            )
        )

    # =====================================================
    # IOC ANALYSIS
    # =====================================================

    story.append(
        Paragraph(
            "4. Indicators of Compromise (IOC)",
            section_style
        )
    )

    if ioc_rows:

        # Prevent an unusually large IOC table.
        display_iocs = ioc_rows[:100]

        ioc_table_data = [
            [
                "IOC Type",
                "Value"
            ]
        ]

        for row in display_iocs:

            ioc_table_data.append([
                Paragraph(
                    _text(row[0]),
                    small_style
                ),
                Paragraph(
                    _text(row[1]),
                    small_style
                )
            ])

        ioc_table = Table(
            ioc_table_data,
            colWidths=[
                45 * mm,
                115 * mm
            ],
            repeatRows=1
        )

        ioc_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#222222")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor("#f7f7f7")
                    ]
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                )
            ])
        )

        story.append(
            ioc_table
        )

        if len(ioc_rows) > 100:
            story.append(
                Paragraph(
                    f"Showing 100 representative IOCs out of "
                    f"{len(ioc_rows)} unique extracted indicators.",
                    small_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No indicators of compromise were extracted.",
                body_style
            )
        )

    # =====================================================
    # MITRE ATT&CK
    # =====================================================

    story.append(
        Paragraph(
            "5. MITRE ATT&CK Mapping",
            section_style
        )
    )

    if mitre:

        mitre_rows = [
            [
                "Technique ID",
                "Technique",
                "Tactic"
            ]
        ]

        for item in mitre:

            mitre_rows.append([
                _text(
                    item["Technique ID"]
                ),
                Paragraph(
                    _text(
                        item["Technique"]
                    ),
                    small_style
                ),
                Paragraph(
                    _text(
                        item["Tactic"]
                    ),
                    small_style
                )
            ])

        mitre_table = Table(
            mitre_rows,
            colWidths=[
                32 * mm,
                78 * mm,
                50 * mm
            ],
            repeatRows=1
        )

        mitre_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#222222")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor("#f7f7f7")
                    ]
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                )
            ])
        )

        story.append(
            mitre_table
        )

    else:

        story.append(
            Paragraph(
                "No MITRE ATT&CK techniques were mapped.",
                body_style
            )
        )

    # =====================================================
    # AI ANALYSIS
    # =====================================================

    story.append(
        Paragraph(
            "6. AI Security Analysis",
            section_style
        )
    )

    ai = data.get(
        "ai_analysis",
        {}
    )

    if isinstance(ai, dict):

        ai_fields = [
            (
                "Threat Classification",
                ai.get(
                    "Threat Classification"
                )
            ),
            (
                "Threat Explanation",
                ai.get(
                    "Threat Explanation"
                )
            ),
            (
                "Executive Summary",
                ai.get(
                    "Executive Summary"
                )
            )
        ]

        for label, value in ai_fields:

            if value:

                story.append(
                    Paragraph(
                        f"<b>{_text(label)}</b>",
                        body_style
                    )
                )

                story.append(
                    Paragraph(
                        _text(value),
                        body_style
                    )
                )

    else:

        story.append(
            Paragraph(
                "No AI security analysis was available.",
                body_style
            )
        )

    # =====================================================
    # RISK ASSESSMENT
    # =====================================================

    story.append(
        Paragraph(
            "7. Risk Assessment",
            section_style
        )
    )

    risk_table = Table(
        [
            [
                "Risk Metric",
                "Assessment"
            ],
            [
                "Risk Score",
                _text(
                    data.get(
                        "risk_score",
                        0
                    )
                )
            ],
            [
                "Severity",
                _text(
                    data.get(
                        "severity",
                        "Low"
                    )
                )
            ]
        ],
        colWidths=[
            70 * mm,
            90 * mm
        ],
        repeatRows=1
    )

    risk_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#222222")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.grey
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#f5f5f5")
                ]
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(
        risk_table
    )

    story.append(
        Spacer(
            1,
            5 * mm
        )
    )

    story.append(
        Paragraph(
            "<b>Risk Explanation:</b> "
            + _text(
                data.get(
                    "risk_explanation",
                    "No risk explanation available."
                )
            ),
            body_style
        )
    )

    # =====================================================
    # RECOMMENDATIONS
    # =====================================================

    story.append(
        Paragraph(
            "8. Security Recommendations",
            section_style
        )
    )

    recommendations = None

    if isinstance(ai, dict):

        recommendations = ai.get(
            "Recommendations"
        )

    if recommendations:

        if isinstance(
            recommendations,
            list
        ):

            for number, recommendation in enumerate(
                recommendations,
                1
            ):

                story.append(
                    Paragraph(
                        f"<b>{number}.</b> "
                        + _text(
                            recommendation
                        ),
                        body_style
                    )
                )

        else:

            story.append(
                Paragraph(
                    _text(
                        recommendations
                    ),
                    body_style
                )
            )

    else:

        default_recommendations = [
            "Investigate identified high and critical security events.",
            "Review affected accounts, hosts, and network sources.",
            "Contain confirmed malicious activity where appropriate.",
            "Monitor extracted indicators for additional related activity.",
            "Apply relevant security controls and remediation measures."
        ]

        for number, recommendation in enumerate(
            default_recommendations,
            1
        ):

            story.append(
                Paragraph(
                    f"<b>{number}.</b> "
                    + recommendation,
                    body_style
                )
            )

    # =====================================================
    # REPRESENTATIVE INCIDENT EVIDENCE
    # =====================================================

    story.append(
        Paragraph(
            "9. Representative Incident Evidence",
            section_style
        )
    )

    if priority_threats:

        for number, threat in enumerate(
            priority_threats,
            1
        ):

            story.append(
                Paragraph(
                    f"<b>{number}. "
                    + _text(
                        threat.get(
                            "type",
                            "Threat"
                        )
                    )
                    + "</b>",
                    body_style
                )
            )

            story.append(
                Paragraph(
                    _text(
                        _threat_evidence(threat)
                    ),
                    small_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No representative incident evidence was available.",
                body_style
            )
        )

    # =====================================================
    # CONCLUSION
    # =====================================================

    story.append(
        Paragraph(
            "10. Conclusion",
            section_style
        )
    )

    conclusion = (
        f"ThreatLens AI analyzed "
        f"{_safe(data.get('total_lines', 0))} log entries "
        f"and identified "
        f"{_safe(data.get('total_threats', len(threats)))} "
        f"security events. The findings were summarized by "
        f"threat category, severity, indicators of compromise, "
        f"and MITRE ATT&CK techniques. Representative evidence "
        f"has been retained in this report while the complete "
        f"log dataset remains available to the investigation workflow."
    )

    story.append(
        Paragraph(
            conclusion,
            body_style
        )
    )

    # =====================================================
    # BUILD PDF
    # =====================================================

    doc.build(
        story,
        onFirstPage=_footer,
        onLaterPages=_footer
    )

    return output_path
