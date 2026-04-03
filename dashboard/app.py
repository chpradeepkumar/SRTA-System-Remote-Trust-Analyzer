from flask import Flask, render_template, jsonify, send_from_directory, redirect, request, session, url_for
import sys, os, psutil, json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "agent"))
sys.path.insert(0, AGENT_PATH)

from scanner import run_scan, get_score

import db


app = Flask(__name__)
app.secret_key = os.environ.get("SRTA_SECRET", "srta-dashboard-secret")

# Processes that indicate remote access tools
REMOTE_TOOLS = [
    "anydesk.exe",
    "teamviewer.exe",
    "ultraviewer.exe",
    "remoting_host.exe",
]

# Critical protected process names
PROTECTED_PROCESSES = {"system", "smss.exe", "csrss.exe", "wininit.exe"}


# Initialize DB
db.init_db()


def compute_system_state(scan_results):
    """Given a list of scan result dicts, compute trust, threat, and flags."""
    if not scan_results:
        return {
            "scanned": False,
            "safe": False,
            "remote": False,
            "trust": 0,
            "threat": None,
            "suspicious_count": 0,
            "connections_count": 0,
        }

    remote_detected = any(bool(p.get("is_remote")) for p in scan_results)

    # suspicious processes: low score (<70) or explicitly remote
    suspicious_count = sum(1 for p in scan_results if int(p.get("score", 100)) < 70 or p.get("is_remote"))

    # aggregate unique outbound endpoints
    conns = set()
    for p in scan_results:
        for c in p.get("connections", []):
            conns.add(c)

    connections_count = len(conns)

    # cpu anomalies
    high_cpu_count = sum(1 for p in scan_results if float(p.get("cpu", 0)) > 50)

    # scoring heuristics (penalties)
    remote_penalty = 50 if remote_detected else 0
    suspicious_penalty = min(40, suspicious_count * 8)
    conn_penalty = min(30, connections_count * 3)
    cpu_penalty = min(20, high_cpu_count * 10)

    trust = max(0, 100 - (remote_penalty + suspicious_penalty + conn_penalty + cpu_penalty))

    if remote_detected:
        # If any remote access tool is present, treat as HIGH threat
        threat = "HIGH"
    else:
        if trust >= 80:
            threat = "LOW"
        elif trust >= 60:
            threat = "MEDIUM"
        else:
            threat = "LOW"

    # For exam gating: only remote access blocks the exam. Other signals are informational.
    system_safe = not remote_detected

    return {
        "scanned": True,
        "safe": system_safe,
        "remote": remote_detected,
        "remote_access_detected": remote_detected,
        "trust": int(trust),
        "threat": threat,
        "threat_level": threat,
        "suspicious_count": suspicious_count,
        "connections_count": connections_count,
    }


def is_logged_in():
    return session.get("logged_in", False)


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username == "admin" and password == "admin123":
            # Reset any previous scan state on new login to avoid reuse
            session.pop("scan_completed", None)
            session.pop("remote_access_detected", None)
            session.pop("last_scan_ts", None)
            session["logged_in"] = True
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid credentials")

    if is_logged_in():
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("home"))
    return render_template("index.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# 🔍 SCAN
@app.route("/scan")
def scan():
    if not is_logged_in():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    try:
        results = run_scan()
    except Exception as exc:
        return jsonify({"success": False, "message": f"Scan failed: {exc}"}), 500

    # persist latest scan and compute state
    ts = None
    try:
        ts = db.save_scan(results)
    except Exception:
        # non-fatal when DB persists fails
        pass

    state = compute_system_state(results)
    try:
        db.set_state("last_state", state)
    except Exception:
        pass

    # bind scan to the user's session so scans are not globally reused
    try:
        session["scan_completed"] = True
        session["remote_access_detected"] = bool(state.get("remote_access_detected", state.get("remote", False)))
        if ts:
            session["last_scan_ts"] = int(ts)
    except Exception:
        pass

    # Structured response: remote detection separate from general trust
    resp = {
        # compatibility: explicit scan_completed flag
        "scan_completed": True,
        "scanned": True,
        "remote_access_detected": state.get("remote_access_detected", state.get("remote", False)),
        "threat_level": state.get("threat_level", state.get("threat")),
        "processes": results,
    }
    return jsonify(resp)


@app.route("/system-status")
def system_status():
    if not is_logged_in():
        return jsonify({"safe": False, "message": "Unauthorized"}), 401
    # Prefer session-bound scan info to avoid reusing scans between sessions
    scan_completed = session.get("scan_completed", False)
    remote_flag = session.get("remote_access_detected") if "remote_access_detected" in session else None

    resp = {
        "scanned": False,
        "scan_completed": bool(scan_completed),
        "remote_access_detected": remote_flag,
        "trust": 0,
        "threat": None,
        "suspicious_count": 0,
        "connections_count": 0,
    }

    # If the session has a scan timestamp, only then expose computed metrics
    last = db.get_last_scan()
    if scan_completed and last and session.get("last_scan_ts") and int(session.get("last_scan_ts")) == int(last.get("ts")):
        scan_results = last.get("results") if last else []
        state = compute_system_state(scan_results)
        resp.update({
            "scanned": state.get("scanned", True),
            "scan_completed": True,
            "remote_access_detected": bool(state.get("remote_access_detected", state.get("remote", False))),
            "remote": state.get("remote", False),
            "trust": state.get("trust", 0),
            "threat": state.get("threat", None),
            "threat_level": state.get("threat_level", state.get("threat", None)),
            "suspicious_count": state.get("suspicious_count", 0),
            "connections_count": state.get("connections_count", 0),
        })

    return jsonify(resp)



@app.route("/processes")
def processes():
    if not is_logged_in():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    # Only return processes for the session that performed the scan
    last = db.get_last_scan()
    if not last:
        return jsonify([])

    last_ts = int(last.get("ts"))
    if session.get("last_scan_ts") and int(session.get("last_scan_ts")) == last_ts:
        return jsonify(last.get("results") or [])

    return jsonify([])


@app.route("/connections")
def connections():
    if not is_logged_in():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    # Only return connections for the session that performed the scan
    last = db.get_last_scan()
    if not last:
        return jsonify([])

    last_ts = int(last.get("ts"))
    if not (session.get("last_scan_ts") and int(session.get("last_scan_ts")) == last_ts):
        return jsonify([])

    results = last.get("results") or []
    conns = []
    for p in results:
        for c in p.get("connections", []):
            conns.append({"process": p.get("name"), "endpoint": c})
    return jsonify(conns)


@app.route("/trust-score")
def trust_score():
    if not is_logged_in():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    # Only compute trust if this session performed the scan
    last = db.get_last_scan()
    if not last or not session.get("last_scan_ts") or int(session.get("last_scan_ts")) != int(last.get("ts")):
        return jsonify({"trust": 0, "threat": None})

    results = last.get("results") if last else []
    state = compute_system_state(results)
    return jsonify({"trust": state.get("trust", 0), "threat": state.get("threat", None)})


@app.route("/kill/<int:pid>", methods=["POST"])
def kill_process(pid):
    if not is_logged_in():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    if pid <= 0:
        return jsonify({"success": False, "message": "Invalid PID supplied."}), 400

    try:
        proc = psutil.Process(pid)
        name = proc.name() or ""
        lowered_name = name.lower()
        score, _ = get_score(name)

        if lowered_name in PROTECTED_PROCESSES:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Critical system processes cannot be terminated.",
                    }
                ),
                403,
            )

        if score > 60:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Only low-trust processes can be terminated.",
                    }
                ),
                403,
            )

        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass

        # refresh scan state (best-effort)
        try:
            new_results = run_scan()
            ts = db.save_scan(new_results)
            db.set_state("last_state", compute_system_state(new_results))
            try:
                session["scan_completed"] = True
                session["last_scan_ts"] = int(ts)
                session["remote_access_detected"] = bool(compute_system_state(new_results).get("remote_access_detected", False))
            except Exception:
                pass
        except Exception:
            pass

        return jsonify({"success": True, "message": f"Process '{name}' ({pid}) terminated successfully."})
    except psutil.NoSuchProcess:
        return jsonify({"success": False, "message": "Process not found."}), 404
    except psutil.AccessDenied:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Access denied while terminating the process.",
                }
            ),
            403,
        )
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 500


# 🔥 EXAM CHECK
@app.route("/check-system", methods=["POST"])
def check_system():
    if not is_logged_in():
        return jsonify({"status": "RISK", "message": "Unauthorized"}), 401
    # Use session-bound scan flags to prevent reuse of previous scans
    if not session.get("scan_completed"):
        return jsonify({"status": "RISK", "message": "Please scan your system before starting the exam."}), 200

    if session.get("remote_access_detected"):
        return jsonify({"status": "RISK", "message": "Remote access tool detected. Close it to continue."}), 200

    return jsonify({"status": "SAFE", "message": "No remote access tools detected."}), 200


# 📝 EXAM PAGE
@app.route("/exam")
def exam():
    if not is_logged_in():
        return redirect(url_for("home"))
    # server-side enforcement: only allow exam when a scan has completed in this session and no remote access tool detected
    if not session.get("scan_completed"):
        return redirect(url_for("dashboard"))

    if session.get("remote_access_detected"):
        return redirect(url_for("dashboard"))

    return render_template("exam.html")


@app.route("/portal")
def portal_root():
    if not is_logged_in():
        return redirect(url_for("home"))
    # ensure system is safe before exposing portal (session-scoped)
    if not session.get("scan_completed"):
        return redirect(url_for("dashboard"))
    if session.get("remote_access_detected"):
        return redirect(url_for("dashboard"))
    return portal_static()


@app.route('/portal/')
@app.route('/portal/<path:filename>')
def portal_static(filename="index.htm"):
    if not is_logged_in():
        return redirect(url_for("home"))
    # session-scoped enforcement
    if not session.get("scan_completed"):
        return redirect(url_for("dashboard"))
    if session.get("remote_access_detected"):
        return redirect(url_for("dashboard"))
    portal_dir = os.path.abspath(os.path.join(BASE_DIR, "..", "portal"))
    return send_from_directory(portal_dir, filename)


if __name__ == "__main__":
    app.run(debug=True)
