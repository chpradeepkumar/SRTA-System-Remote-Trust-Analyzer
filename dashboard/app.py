from flask import Flask, render_template, jsonify, request, send_file
import sys, os, psutil, datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "agent"))
sys.path.insert(0, AGENT_PATH)

from scanner import run_scan

app = Flask(__name__)

score_history = []
PROTECTED = ["svchost.exe", "lsass.exe", "wininit.exe", "csrss.exe", "services.exe"]

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["GET", "POST"])
def scan():
    results = run_scan()
    avg_score = sum(r['score'] for r in results) / len(results)
    score_history.append(round(avg_score))
    if len(score_history) > 30:
        score_history.pop(0)
    return jsonify(results)


@app.route("/history")
def history():
    return jsonify(score_history)


@app.route("/kill", methods=["POST"])
def kill():
    pid = request.json.get("pid")
    try:
        p = psutil.Process(pid)
        if p.name().lower() in PROTECTED:
            return jsonify({"error": "Protected system process"}), 403
        p.terminate()
        return jsonify({"status": "Process terminated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/connections")
def connections():
    conns = []
    for c in psutil.net_connections(kind='inet'):
        if c.raddr:
            conns.append({
                "local": f"{c.laddr.ip}:{c.laddr.port}",
                "remote": f"{c.raddr.ip}:{c.raddr.port}",
                "status": c.status
            })
    return jsonify(conns)


@app.route("/export")
def export():
    file_path = "srta_report.pdf"
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(file_path)
    elements = []

    results = run_scan()

    # Title
    elements.append(Paragraph("SRTA Security Assessment Report", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Generated: {datetime.datetime.now()}", styles['Normal']))
    elements.append(Spacer(1, 20))

    # Summary
    avg_score = sum(r['score'] for r in results) / len(results)
    threat_level = "HIGH" if avg_score < 50 else "MEDIUM" if avg_score < 80 else "SAFE"

    elements.append(Paragraph(f"Overall System Trust Score: {round(avg_score)} / 100", styles['Heading2']))
    elements.append(Paragraph(f"System Threat Level: {threat_level}", styles['Heading2']))
    elements.append(Spacer(1, 20))

    def build_table(title, data, headers, color):
        elements.append(Paragraph(title, styles['Heading3']))
        elements.append(Spacer(1, 8))

        table_data = [headers]
        table_data.extend(data)

        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BACKGROUND',(0,1),(-1,-1), color)
        ]))

        elements.append(table)
        elements.append(Spacer(1, 15))

    # Process risk sections
    high = [[r['name'], r['cpu'], r['score'], r['reason']] for r in results if r['score'] < 50]
    medium = [[r['name'], r['cpu'], r['score'], r['reason']] for r in results if 50 <= r['score'] < 80]
    safe = [[r['name'], r['cpu'], r['score'], r['reason']] for r in results if r['score'] >= 80]

    if high:
        build_table("High Risk Processes", high, ["Process", "CPU %", "Trust Score", "Reason"], colors.lightcoral)
    if medium:
        build_table("Medium Risk Processes", medium, ["Process", "CPU %", "Trust Score", "Reason"], colors.lightyellow)
    if safe:
        build_table("Safe Processes", safe, ["Process", "CPU %", "Trust Score", "Reason"], colors.lightgreen)

    # 🌐 Active Network Connections Section
    connections = []
    for c in psutil.net_connections(kind='inet'):
        if c.raddr:
            connections.append([
                f"{c.laddr.ip}:{c.laddr.port}",
                f"{c.raddr.ip}:{c.raddr.port}",
                c.status
            ])

    if connections:
        build_table("Active Network Connections", connections,
                    ["Local Address", "Remote Address", "Status"],
                    colors.lightblue)

    doc.build(elements)
    return send_file(file_path, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
