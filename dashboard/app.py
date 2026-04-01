# from flask import Flask, render_template, jsonify, request, send_file
# import sys, os, psutil, datetime

# # ---------------- PATH SETUP ----------------
# BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# AGENT_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "agent"))
# sys.path.insert(0, AGENT_PATH)

# from scanner import run_scan

# # ---------------- APP INIT ----------------
# app = Flask(__name__)

# # ---------------- GLOBAL DATA ----------------
# score_history = []

# PROTECTED = [
#     "svchost.exe",
#     "lsass.exe",
#     "wininit.exe",
#     "csrss.exe",
#     "services.exe",
#     "system",
#     "system idle process"
# ]

# # 🔥 REMOTE TOOLS (FINAL)
# REMOTE_TOOLS = [
#     "anydesk",
#     "teamviewer",
#     "rustdesk",
#     "mstsc"
# ]

# # ---------------- ROUTES ----------------

# @app.route("/")
# def home():
#     return render_template("index.html")


# # 🔍 RUN SCAN
# @app.route("/scan", methods=["GET"])
# def scan():
#     results = run_scan()

#     if not results:
#         return jsonify([])

#     avg = sum(p["score"] for p in results) / len(results)
#     score_history.append(round(avg))

#     if len(score_history) > 30:
#         score_history.pop(0)

#     return jsonify(results)


# # 🔥 ✅ NEW: EXAM CHECK (WORKING)
# @app.route("/check-system", methods=["POST"])
# def check_system():

#     for proc in psutil.process_iter():
#         try:
#             name = proc.name().lower()

#             for tool in REMOTE_TOOLS:
#                 if tool in name:
#                     return jsonify({
#                         "status": "RISK",
#                         "message": f"Remote Tool Detected: {name}"
#                     })

#         except:
#             continue

#     return jsonify({
#         "status": "SAFE",
#         "message": "System Secure"
#     })


# # 📈 HISTORY
# @app.route("/history")
# def history():
#     return jsonify(score_history)


# # ❌ KILL PROCESS
# @app.route("/kill", methods=["POST"])
# def kill_process():
#     data = request.get_json()
#     pid = data.get("pid")

#     if not pid:
#         return jsonify({"error": "PID not provided"}), 400

#     try:
#         target = psutil.Process(pid)
#         name = target.name().lower()

#         if name in PROTECTED:
#             return jsonify({
#                 "error": "Protected system process. Action blocked."
#             }), 403

#         killed = 0

#         for proc in psutil.process_iter(["pid", "name"]):
#             try:
#                 if proc.info["name"] and proc.info["name"].lower() == name:
#                     proc.terminate()
#                     killed += 1
#             except:
#                 pass

#         if killed == 0:
#             return jsonify({
#                 "error": "No process terminated"
#             }), 403

#         return jsonify({
#             "status": f"{killed} process(es) terminated"
#         })

#     except:
#         return jsonify({"error": "failed"}), 500


# # 🌐 CONNECTIONS
# @app.route("/connections")
# def connections():
#     conns = []

#     for c in psutil.net_connections(kind="inet"):
#         if c.raddr:
#             conns.append({
#                 "local": f"{c.laddr.ip}:{c.laddr.port}",
#                 "remote": f"{c.raddr.ip}:{c.raddr.port}",
#                 "status": c.status
#             })

#     return jsonify(conns)


# # 📄 EXPORT PDF
# @app.route("/export")
# def export_pdf():
#     from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
#     from reportlab.lib.styles import getSampleStyleSheet
#     from reportlab.lib import colors

#     file_name = "srta_report.pdf"
#     doc = SimpleDocTemplate(file_name)
#     styles = getSampleStyleSheet()
#     elements = []

#     results = run_scan()

#     elements.append(Paragraph("SRTA Report", styles["Title"]))
#     elements.append(Spacer(1, 20))

#     if results:
#         table_data = [["Process", "CPU", "Score"]]

#         for p in results:
#             table_data.append([p["name"], p["cpu"], p["score"]])

#         table = Table(table_data)
#         table.setStyle(TableStyle([
#             ("GRID", (0,0), (-1,-1), 1, colors.black),
#         ]))

#         elements.append(table)

#     doc.build(elements)
#     return send_file(file_name, as_attachment=True)


# # ---------------- RUN ----------------
# if __name__ == "__main__":
#     app.run(debug=True)

from flask import Flask, render_template, jsonify
import sys, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "agent"))
sys.path.insert(0, AGENT_PATH)

from scanner import run_scan
import psutil

app = Flask(__name__)

REMOTE_TOOLS = ["anydesk","teamviewer","rustdesk","mstsc"]

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan")
def scan():
    return jsonify(run_scan())


# 🔥 EXAM CHECK
@app.route("/check-system", methods=["POST"])
def check_system():

    for proc in psutil.process_iter():
        try:
            name = proc.name().lower()

            for tool in REMOTE_TOOLS:
                if tool in name:
                    return jsonify({"status": "RISK"})
        except:
            continue

    return jsonify({"status": "SAFE"})


# ✅ FIXED EXAM PAGE
@app.route("/exam")
def exam():
    return render_template("exam.html")   # 👈 important


if __name__ == "__main__":
    app.run(debug=True)