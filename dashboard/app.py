from flask import Flask, render_template, jsonify, request, send_file
import sys, os, psutil, datetime

# ---------------- PATH SETUP ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "agent"))
sys.path.insert(0, AGENT_PATH)

from scanner import run_scan

# ---------------- APP INIT ----------------
app = Flask(__name__)

# ---------------- GLOBAL DATA ----------------
score_history = []

# ❗ NEVER allow these to be killed
PROTECTED = [
    "svchost.exe",
    "lsass.exe",
    "wininit.exe",
    "csrss.exe",
    "services.exe",
    "system",
    "system idle process"
]

# ---------------- ROUTES ----------------

@app.route("/")
def home():
    return render_template("index.html")


# 🔍 RUN SCAN
@app.route("/scan", methods=["GET"])
def scan():
    results = run_scan()

    if not results:
        return jsonify([])

    avg = sum(p["score"] for p in results) / len(results)
    score_history.append(round(avg))

    if len(score_history) > 30:
        score_history.pop(0)

    return jsonify(results)


# 📈 HISTORY (optional)
@app.route("/history")
def history():
    return jsonify(score_history)


# ❌ KILL PROCESS (GROUP-BASED)
@app.route("/kill", methods=["POST"])
def kill_process():
    data = request.get_json()
    pid = data.get("pid")

    if not pid:
        return jsonify({"error": "PID not provided"}), 400

    try:
        target = psutil.Process(pid)
        name = target.name().lower()

        # 🔐 Safety check
        if name in PROTECTED:
            return jsonify({
                "error": "Protected system process. Action blocked."
            }), 403

        killed = 0

        # 🔥 KILL ALL PROCESSES WITH SAME NAME (Chrome fix)
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"] and proc.info["name"].lower() == name:
                    proc.terminate()
                    killed += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        if killed == 0:
            return jsonify({
                "error": "No process terminated (permission issue)"
            }), 403

        return jsonify({
            "status": f"{killed} process(es) of {name} terminated successfully"
        })

    except psutil.NoSuchProcess:
        return jsonify({"error": "Process already closed"}), 404

    except psutil.AccessDenied:
        return jsonify({"error": "Access denied. Run app as administrator"}), 403

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 🌐 NETWORK CONNECTIONS
@app.route("/connections")
def connections():
    conns = []

    for c in psutil.net_connections(kind="inet"):
        if c.raddr:
            conns.append({
                "local": f"{c.laddr.ip}:{c.laddr.port}",
                "remote": f"{c.raddr.ip}:{c.raddr.port}",
                "status": c.status
            })

    return jsonify(conns)


# 📄 EXPORT PDF REPORT
@app.route("/export")
def export_pdf():
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors

    file_name = "srta_report.pdf"
    doc = SimpleDocTemplate(file_name)
    styles = getSampleStyleSheet()
    elements = []

    results = run_scan()

    elements.append(Paragraph("SRTA – Security Assessment Report", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(
        f"Generated on: {datetime.datetime.now()}",
        styles["Normal"]
    ))
    elements.append(Spacer(1, 20))

    if results:
        avg = round(sum(p["score"] for p in results) / len(results))
        threat = "HIGH" if avg < 50 else "MEDIUM" if avg < 80 else "SAFE"

        elements.append(Paragraph(
            f"Overall Trust Score: {avg} / 100",
            styles["Heading2"]
        ))
        elements.append(Paragraph(
            f"Threat Level: {threat}",
            styles["Heading2"]
        ))
        elements.append(Spacer(1, 20))

        table_data = [["Process", "CPU %", "Trust Score", "Reason"]]

        for p in results:
            table_data.append([
                p["name"],
                p["cpu"],
                p["score"],
                p["reason"]
            ])

        table = Table(table_data)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.grey),
            ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
            ("GRID", (0,0), (-1,-1), 1, colors.black),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ]))

        elements.append(table)

    doc.build(elements)
    return send_file(file_name, as_attachment=True)


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
