"""
Phase 5 Week 14 — Automated Forensic PDF Report Generator
Auto-generates professional incident reports after every attack.
"""

import os
import json
import time
from reportlab.lib.pagesizes    import A4
from reportlab.lib.styles       import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units        import mm
from reportlab.lib              import colors
from reportlab.platypus         import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.enums        import TA_CENTER, TA_LEFT, TA_RIGHT

# ── Paths ─────────────────────────────────────────────────────
REPORTS_DIR = "/app/logs/reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Colors ────────────────────────────────────────────────────
COLOR_RED     = colors.HexColor("#E53E3E")
COLOR_ORANGE  = colors.HexColor("#DD6B20")
COLOR_YELLOW  = colors.HexColor("#D69E2E")
COLOR_GREEN   = colors.HexColor("#38A169")
COLOR_BLUE    = colors.HexColor("#3182CE")
COLOR_DARK    = colors.HexColor("#1A202C")
COLOR_GRAY    = colors.HexColor("#718096")
COLOR_LIGHT   = colors.HexColor("#F7FAFC")
COLOR_HEADER  = colors.HexColor("#2D3748")


def get_level_color(level):
    """Return color for threat level."""
    return {
        "CRITICAL": COLOR_RED,
        "HIGH"    : COLOR_ORANGE,
        "MEDIUM"  : COLOR_YELLOW,
        "LOW"     : COLOR_GREEN,
        "INFO"    : COLOR_BLUE,
        "LAB"     : COLOR_GRAY,
    }.get(level, COLOR_GRAY)


def get_mitigation_color(level_num):
    """Return color for mitigation level number."""
    return {
        1: COLOR_GREEN,
        2: COLOR_YELLOW,
        3: COLOR_ORANGE,
        4: COLOR_RED,
        5: colors.HexColor("#742A2A"),
    }.get(level_num, COLOR_GRAY)


class ForensicReportGenerator:
    """Generates professional PDF incident reports."""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Define custom paragraph styles."""
        self.title_style = ParagraphStyle(
            "ReportTitle",
            parent    = self.styles["Title"],
            fontSize  = 24,
            textColor = COLOR_DARK,
            spaceAfter= 6,
            alignment = TA_CENTER,
        )
        self.subtitle_style = ParagraphStyle(
            "Subtitle",
            parent    = self.styles["Normal"],
            fontSize  = 11,
            textColor = COLOR_GRAY,
            alignment = TA_CENTER,
            spaceAfter= 20,
        )
        self.section_style = ParagraphStyle(
            "SectionHeader",
            parent      = self.styles["Heading1"],
            fontSize    = 14,
            textColor   = COLOR_HEADER,
            borderPad   = 4,
            spaceAfter  = 8,
            spaceBefore = 16,
        )
        self.body_style = ParagraphStyle(
            "Body",
            parent    = self.styles["Normal"],
            fontSize  = 10,
            textColor = COLOR_DARK,
            spaceAfter= 6,
            leading   = 14,
        )
        self.caption_style = ParagraphStyle(
            "Caption",
            parent    = self.styles["Normal"],
            fontSize  = 8,
            textColor = COLOR_GRAY,
            alignment = TA_CENTER,
        )

    def _make_header_table(self, incident_id, timestamp):
        """Create the report header box."""
        data = [[
            Paragraph(
                f"<b>INCIDENT REPORT</b><br/>"
                f"<font size='9' color='gray'>ID: {incident_id}</font>",
                self.title_style
            ),
            Paragraph(
                f"<font size='9'>Generated: {timestamp}<br/>"
                f"Classification: CONFIDENTIAL<br/>"
                f"DDoS Mitigation Tool v2.0</font>",
                ParagraphStyle(
                    "HeaderRight",
                    parent    = self.styles["Normal"],
                    fontSize  = 9,
                    textColor = COLOR_GRAY,
                    alignment = TA_RIGHT,
                )
            )
        ]]
        table = Table(data, colWidths=[120*mm, 60*mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), COLOR_LIGHT),
            ("BOX",        (0,0), (-1,-1), 1, COLOR_BLUE),
            ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING",(0,0), (-1,-1), 12),
            ("RIGHTPADDING",(0,0),(-1,-1), 12),
            ("TOPPADDING", (0,0), (-1,-1), 12),
            ("BOTTOMPADDING",(0,0),(-1,-1),12),
        ]))
        return table

    def _make_summary_table(self, summary_data):
        """Create executive summary table."""
        rows = []
        for key, value, color in summary_data:
            rows.append([
                Paragraph(f"<b>{key}</b>", self.body_style),
                Paragraph(
                    f"<font color='{color.hexval() if hasattr(color,'hexval') else '#000000'}'>"
                    f"<b>{value}</b></font>",
                    self.body_style
                )
            ])

        table = Table(rows, colWidths=[80*mm, 100*mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), COLOR_LIGHT),
            ("ROWBACKGROUNDS", (0,0), (-1,-1),
             [colors.white, COLOR_LIGHT]),
            ("BOX",        (0,0), (-1,-1), 0.5, COLOR_GRAY),
            ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#E2E8F0")),
            ("LEFTPADDING",(0,0), (-1,-1), 8),
            ("RIGHTPADDING",(0,0),(-1,-1), 8),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ]))
        return table

    def _make_timeline_table(self, events):
        """Create timeline events table."""
        headers = ["Time", "Elapsed", "Event", "IP", "Details"]
        rows    = [headers]

        for event in events[:50]:   # max 50 events in table
            detail = ""
            if event["event_type"] == "ALERT":
                detail = (f"Type:{event.get('attack_type','?')} "
                         f"Score:{event.get('threat_score','?')} "
                         f"PPS:{event.get('pps','?')}")
            elif event["event_type"] == "MITIGATION":
                detail = (f"L{event.get('level','?')} "
                         f"{event.get('name','?')} "
                         f"({event.get('action','?')})")

            rows.append([
                event.get("timestamp", "")[-8:],  # time only
                f"{event.get('elapsed_s','0')}s",
                event.get("event_type", ""),
                event.get("ip", ""),
                detail[:50],
            ])

        col_widths = [20*mm, 18*mm, 22*mm, 32*mm, 88*mm]
        table      = Table(rows, colWidths=col_widths)

        style = [
            ("BACKGROUND",  (0,0), (-1,0),  COLOR_HEADER),
            ("TEXTCOLOR",   (0,0), (-1,0),  colors.white),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),
             [colors.white, COLOR_LIGHT]),
            ("BOX",         (0,0), (-1,-1), 0.5, COLOR_GRAY),
            ("GRID",        (0,0), (-1,-1), 0.3,
             colors.HexColor("#E2E8F0")),
            ("LEFTPADDING", (0,0), (-1,-1), 4),
            ("RIGHTPADDING",(0,0), (-1,-1), 4),
            ("TOPPADDING",  (0,0), (-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
        ]

        # Color code event types
        for i, event in enumerate(events[:50], 1):
            et = event.get("event_type", "")
            if et == "ALERT":
                style.append(("TEXTCOLOR",(2,i),(2,i), COLOR_RED))
            elif et == "MITIGATION":
                style.append(("TEXTCOLOR",(2,i),(2,i), COLOR_ORANGE))
            elif et == "NORMAL":
                style.append(("TEXTCOLOR",(2,i),(2,i), COLOR_GREEN))

        table.setStyle(TableStyle(style))
        return table

    def generate(self, timeline_path, pcap_path=None, intel_data=None):
        """
        Generate complete forensic PDF report.
        Returns path to generated PDF.
        """
        # Load timeline data
        with open(timeline_path) as f:
            timeline = json.load(f)

        attack_id  = timeline.get("attack_id", "unknown")
        pdf_path   = f"{REPORTS_DIR}/incident_{attack_id}.pdf"
        timestamp  = time.strftime("%Y-%m-%d %H:%M:%S")

        doc    = SimpleDocTemplate(
            pdf_path,
            pagesize     = A4,
            rightMargin  = 20*mm,
            leftMargin   = 20*mm,
            topMargin    = 20*mm,
            bottomMargin = 20*mm,
        )

        story  = []

        # ── Page 1: Executive Summary ─────────────────────────
        story.append(
            self._make_header_table(attack_id, timestamp)
        )
        story.append(Spacer(1, 12))

        # Section 1 — Overview
        story.append(
            Paragraph("1. EXECUTIVE SUMMARY", self.section_style)
        )
        story.append(HRFlowable(
            width="100%", thickness=1,
            color=COLOR_BLUE, spaceAfter=8
        ))

        # Get IP summaries
        ip_summaries = timeline.get("ip_summaries", {})
        total_events = timeline.get("total_events", 0)

        # Find primary attacker
        primary_ip    = ""
        primary_stats = {}
        max_alerts    = 0

        for ip, stats in ip_summaries.items():
            if stats.get("total_alerts", 0) > max_alerts:
                max_alerts    = stats["total_alerts"]
                primary_ip    = ip
                primary_stats = stats

        attack_types = primary_stats.get("attack_types", [])
        max_score    = primary_stats.get("max_threat_score", 0)
        peak_pps     = primary_stats.get("peak_pps", 0)
        duration     = primary_stats.get("duration_seconds", 0)
        mit_levels   = primary_stats.get("mitigation_levels", [])

        # Determine overall threat level
        if max_score >= 85:
            threat_level = "CRITICAL"
        elif max_score >= 70:
            threat_level = "HIGH"
        elif max_score >= 55:
            threat_level = "MEDIUM"
        elif max_score >= 40:
            threat_level = "LOW"
        else:
            threat_level = "INFO"

        level_color = get_level_color(threat_level)

        summary_rows = [
            ("Incident ID",
             attack_id,                           COLOR_DARK),
            ("Detection Time",
             timeline.get("generated_at","?"),    COLOR_DARK),
            ("Primary Attacker",
             primary_ip or "Unknown",             COLOR_RED),
            ("Attack Types",
             ", ".join(attack_types) or "Unknown",COLOR_ORANGE),
            ("Overall Threat Level",
             threat_level,                        level_color),
            ("Max Threat Score",
             f"{max_score}/100",                  level_color),
            ("Peak Packet Rate",
             f"{peak_pps} pps",                   COLOR_DARK),
            ("Attack Duration",
             f"{duration} seconds",               COLOR_DARK),
            ("Total Events Logged",
             str(total_events),                   COLOR_DARK),
            ("Mitigation Applied",
             ", ".join([f"L{l}" for l in mit_levels])
             if mit_levels else "L1 Monitor only",COLOR_DARK),
            ("PCAP Evidence",
             os.path.basename(pcap_path)
             if pcap_path else "Not captured",    COLOR_DARK),
        ]

        story.append(self._make_summary_table(summary_rows))
        story.append(Spacer(1, 12))

        # Executive plain-English summary
        story.append(
            Paragraph("Incident Overview", self.section_style)
        )
        summary_text = (
            f"On {timeline.get('generated_at','unknown date')}, the DDoS Mitigation "
            f"Tool detected and responded to a {threat_level}-severity attack "
            f"originating from IP address <b>{primary_ip}</b>. "
            f"The attack lasted approximately <b>{duration} seconds</b> and was "
            f"classified as <b>{', '.join(attack_types)}</b> with a peak packet rate "
            f"of <b>{peak_pps} packets per second</b>. "
            f"The system automatically applied mitigation at levels "
            f"<b>{', '.join([f'L{l}' for l in mit_levels]) if mit_levels else 'L1'}</b>, "
            f"dropping malicious traffic while maintaining service availability. "
            f"A total of <b>{total_events} events</b> were logged during the incident."
        )
        story.append(Paragraph(summary_text, self.body_style))
        story.append(Spacer(1, 8))

        # ── Page 2: Attack Timeline ───────────────────────────
        story.append(PageBreak())
        story.append(
            Paragraph("2. ATTACK TIMELINE", self.section_style)
        )
        story.append(HRFlowable(
            width="100%", thickness=1,
            color=COLOR_BLUE, spaceAfter=8
        ))

        events = timeline.get("events", [])
        if events:
            story.append(self._make_timeline_table(events))
            if len(events) > 50:
                story.append(Spacer(1,4))
                story.append(Paragraph(
                    f"Note: Showing first 50 of {len(events)} events. "
                    f"Full timeline in JSON file.",
                    self.caption_style
                ))
        else:
            story.append(
                Paragraph("No timeline events recorded.", self.body_style)
            )

        # ── Page 3: Technical Details ─────────────────────────
        story.append(PageBreak())
        story.append(
            Paragraph("3. TECHNICAL ANALYSIS", self.section_style)
        )
        story.append(HRFlowable(
            width="100%", thickness=1,
            color=COLOR_BLUE, spaceAfter=8
        ))

        # Per-IP breakdown
        for ip, stats in ip_summaries.items():
            if stats.get("total_alerts", 0) == 0:
                continue

            story.append(
                Paragraph(f"Source IP: {ip}", self.section_style)
            )

            ip_rows = [
                ("IP Address",       ip,                         COLOR_DARK),
                ("First Seen",
                 time.strftime(
                     "%Y-%m-%d %H:%M:%S",
                     time.localtime(stats.get("first_seen", 0))
                 ) if stats.get("first_seen") else "Unknown",    COLOR_DARK),
                ("Last Seen",
                 time.strftime(
                     "%Y-%m-%d %H:%M:%S",
                     time.localtime(stats.get("last_seen", 0))
                 ) if stats.get("last_seen") else "Unknown",     COLOR_DARK),
                ("Total Alerts",
                 str(stats.get("total_alerts", 0)),              COLOR_RED),
                ("Peak PPS",
                 str(stats.get("peak_pps", 0)),                  COLOR_ORANGE),
                ("Attack Types",
                 ", ".join(stats.get("attack_types", [])),       COLOR_ORANGE),
                ("Max Threat Score",
                 f"{stats.get('max_score', 0)}/100",             COLOR_RED),
                ("Mitigation Levels",
                 ", ".join([
                     f"L{l}" for l in
                     stats.get("mitigation_levels", [])
                 ]),                                             COLOR_DARK),
            ]
            story.append(self._make_summary_table(ip_rows))
            story.append(Spacer(1, 8))

        # ── Recommendations ───────────────────────────────────
        story.append(
            Paragraph("4. RECOMMENDATIONS", self.section_style)
        )
        story.append(HRFlowable(
            width="100%", thickness=1,
            color=COLOR_BLUE, spaceAfter=8
        ))

        recommendations = []
        if max_score >= 70:
            recommendations.append(
                "Permanently blacklist the attacking IP address."
            )
        if "SYN_FLOOD" in attack_types:
            recommendations.append(
                "Enable SYN cookies on the server to mitigate future SYN floods."
            )
        if "UDP_FLOOD" in attack_types:
            recommendations.append(
                "Consider blocking UDP traffic on non-essential ports at the ISP level."
            )
        if "HTTP_FLOOD" in attack_types:
            recommendations.append(
                "Implement CAPTCHA challenges for high-volume HTTP requests."
            )
        if duration > 60:
            recommendations.append(
                "Extended attack duration detected — consider contacting ISP for "
                "upstream null routing."
            )
        recommendations.append(
            "Review and update baseline traffic patterns to improve detection accuracy."
        )
        recommendations.append(
            "Analyze PCAP capture file in Wireshark for deep packet inspection."
        )

        for i, rec in enumerate(recommendations, 1):
            story.append(
                Paragraph(f"{i}. {rec}", self.body_style)
            )

        # ── Footer ────────────────────────────────────────────
        story.append(Spacer(1, 20))
        story.append(HRFlowable(
            width="100%", thickness=0.5,
            color=COLOR_GRAY, spaceAfter=6
        ))
        story.append(Paragraph(
            f"Generated by DDoS Mitigation Tool v2.0 | "
            f"{timestamp} | CONFIDENTIAL",
            self.caption_style
        ))

        # Build PDF
        doc.build(story)
        size_kb = os.path.getsize(pdf_path) / 1024
        print(f"          📄 PDF Report → {pdf_path} ({size_kb:.1f}KB)")
        return pdf_path


# ── Global instance ───────────────────────────────────────────
report_generator = ForensicReportGenerator()

