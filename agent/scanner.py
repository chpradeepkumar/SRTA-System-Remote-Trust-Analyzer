import psutil

REMOTE_TOOLS = ["anydesk","teamviewer","rustdesk","mstsc"]

SYSTEM_PROCESSES = [
    "system","system idle process","svchost.exe","lsass.exe",
    "wininit.exe","csrss.exe","services.exe","explorer.exe"
]

def get_score(name):

    lname = name.lower()

    if any(tool in lname for tool in REMOTE_TOOLS):
        return 15, "Remote Tool"

    if lname in SYSTEM_PROCESSES:
        return 95, "System"

    return 60, "Normal"


def run_scan():
    results = []

    for proc in psutil.process_iter(['pid','name']):
        try:
            name = proc.info['name']
            if not name:
                continue

            cpu = proc.cpu_percent(interval=0)

            score, reason = get_score(name)

            # 🔥 GET CONNECTIONS
            conns = []
            try:
                connections = proc.connections(kind='inet')
                for c in connections:
                    if c.raddr:
                        ip = f"{c.raddr.ip}:{c.raddr.port}"
                        conns.append(ip)
            except:
                pass

            results.append({
                "name": name,
                "pid": proc.info['pid'],
                "cpu": cpu,
                "score": score,
                "reason": reason,
                "connections": conns  # 🔥 IMPORTANT
            })

        except:
            continue

    results.sort(key=lambda x: x['score'])
    return results