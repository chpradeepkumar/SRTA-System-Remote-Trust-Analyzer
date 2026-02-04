import psutil, os, json, win32api
from collections import defaultdict

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "scan_results.json")

REMOTE_TOOLS = ["anydesk.exe","teamviewer.exe","rustdesk.exe","mstsc.exe"]
SAFE_SYSTEM = ["explorer.exe","svchost.exe","services.exe","lsass.exe","wininit.exe","csrss.exe","cmd.exe"]
TRUSTED_COMPANIES = ["microsoft","google","adobe","intel","nvidia","mozilla","oracle","vmware"]

cpu_history = defaultdict(list)

def detect_anomaly(name, cpu):
    hist = cpu_history[name]
    hist.append(cpu)
    if len(hist) > 10: hist.pop(0)
    avg = sum(hist) / len(hist)
    return cpu > avg * 2 and cpu > 30

def get_publisher(path):
    try:
        if not path or not os.path.exists(path): return "Unknown"
        info = win32api.GetFileVersionInfo(path, "\\")
        lang, codepage = win32api.VerQueryValue(info, '\\VarFileInfo\\Translation')[0]
        str_info_path = f'\\StringFileInfo\\{lang:04x}{codepage:04x}\\CompanyName'
        return win32api.VerQueryValue(info, str_info_path)
    except:
        return "Unknown"

def calculate_score(name, publisher):
    lname = name.lower()
    pub = publisher.lower()
    if lname in REMOTE_TOOLS: return 20, "Remote Access Tool"
    if lname in SAFE_SYSTEM: return 95, "Windows System Process"
    for t in TRUSTED_COMPANIES:
        if t in pub: return 90, f"Trusted Publisher ({publisher})"
    if publisher == "Unknown": return 50, "Unknown Publisher"
    return 60, f"Third Party ({publisher})"

def run_scan():
    results=[]
    for proc in psutil.process_iter(['pid','name','exe']):
        try:
            name=proc.info['name']
            if not name or name.lower() in ["system idle process","idle"]: continue
            path=proc.info['exe']
            publisher=get_publisher(path)
            base_score, reason = calculate_score(name,publisher)

            cpu=min(proc.cpu_percent(interval=0.1),100)
            memory=proc.memory_info().rss/(1024*1024)
            connections=len(proc.connections(kind='inet'))
            anomaly=detect_anomaly(name,cpu)

            if anomaly: base_score-=20

            results.append({
                "name":name,
                "pid":proc.info['pid'],
                "publisher":publisher,
                "cpu":round(cpu,1),
                "memory":round(memory,1),
                "connections":connections,
                "score":max(base_score,5),
                "anomaly":anomaly,
                "reason":reason + (" | Anomaly" if anomaly else "")
            })
        except: continue

    results.sort(key=lambda x:x['score'])
    with open(DATA_PATH,"w") as f: json.dump(results,f,indent=4)
    return results
