import psutil
import time

REMOTE_TOOLS = [
    "anydesk.exe",
    "teamviewer.exe",
    "ultraviewer.exe",
    "remoting_host.exe",
    "remoting_me2me_host.exe",
    "chromoting_host.exe",
    "mstsc.exe",
]

SYSTEM_PROCESSES = [
    "system","system idle process","svchost.exe","lsass.exe",
    "wininit.exe","csrss.exe","services.exe","explorer.exe"
]

def get_score(name):

    # More robust scoring: base high for normal/system, low for remote tools
    lname = (name or "").lower()

    if lname in REMOTE_TOOLS:
        return 20, "Remote Tool Detected"

    if lname in SYSTEM_PROCESSES:
        return 95, "System"

    # Default to a high trust for regular processes; CPU and connections may reduce it
    return 90, "Normal"


def run_scan():
    results = []

    # Warm up CPU counters so sorting reflects actual values more reliably.
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc.cpu_percent(None)
        except:
            continue

    time.sleep(0.12)


    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info.get('name')
            if not name:
                continue

            # CPU reading
            try:
                cpu = proc.cpu_percent(None)
            except Exception:
                cpu = 0.0

            # connections (best-effort)
            conns = []
            try:
                connections = proc.connections(kind='inet')
                for c in connections:
                    if c.raddr:
                        ip = f"{c.raddr.ip}:{c.raddr.port}"
                        conns.append(ip)
            except Exception:
                conns = []

            base_score, reason = get_score(name)

            # Adjust score for CPU and connections
            score = int(base_score)
            extra_reasons = []

            if cpu is None:
                cpu = 0.0

            if cpu > 50:
                score = max(20, score - 30)
                extra_reasons.append('High CPU')
            elif cpu > 20:
                score = max(30, score - 10)
                extra_reasons.append('Elevated CPU')

            if conns:
                # penalty proportional to unique remote endpoints
                score = max(20, score - min(30, len(set(conns)) * 3))
                extra_reasons.append('Network Activity')

            if extra_reasons:
                reason = reason + ' • ' + ', '.join(extra_reasons)

            results.append({
                'name': name,
                'pid': proc.info.get('pid'),
                'cpu': float(cpu),
                'score': score,
                'reason': reason,
                'is_remote': name.lower() in REMOTE_TOOLS,
                'connections': conns,
            })

        except Exception:
            continue

    results.sort(key=lambda x: x['score'])
    return results
