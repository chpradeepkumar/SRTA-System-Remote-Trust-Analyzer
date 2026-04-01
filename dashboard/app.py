from flask import Flask, render_template, jsonify
import sys, os, psutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "agent"))
sys.path.insert(0, AGENT_PATH)

from scanner import run_scan

app = Flask(__name__)

REMOTE_TOOLS = ["anydesk","teamviewer","rustdesk","mstsc"]

@app.route("/")
def home():
    return render_template("index.html")


# 🔍 SCAN
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


# 📝 EXAM PAGE
@app.route("/exam")
def exam():
    return render_template("exam.html")


if __name__ == "__main__":
    app.run(debug=True)