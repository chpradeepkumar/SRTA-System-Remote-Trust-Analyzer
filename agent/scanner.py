# # # import psutil

# # # REMOTE_TOOLS = [
# # #     "anydesk",
# # #     "teamviewer",
# # #     "rustdesk",
# # #     "mstsc"
# # # ]

# # # def run_scan():
# # #     results = []

# # #     for proc in psutil.process_iter(['pid','name']):
# # #         try:
# # #             name = proc.info['name']

# # #             if not name:
# # #                 continue

# # #             cpu = proc.cpu_percent(interval=0.1)

# # #             score = 90
# # #             reason = "Safe"

# # #             lname = name.lower()

# # #             for tool in REMOTE_TOOLS:
# # #                 if tool in lname:
# # #                     score = 20
# # #                     reason = "Remote Tool"

# # #             results.append({
# # #                 "name": name,
# # #                 "pid": proc.info['pid'],
# # #                 "cpu": round(cpu,1),
# # #                 "score": score,
# # #                 "reason": reason
# # #             })

# # #         except:
# # #             continue

# # #     return results

# # import psutil

# # REMOTE_TOOLS = ["anydesk","teamviewer","rustdesk","mstsc"]

# # SYSTEM_PROCESSES = [
# #     "system","system idle process","svchost.exe","lsass.exe",
# #     "wininit.exe","csrss.exe","services.exe","explorer.exe"
# # ]

# # TRUSTED_APPS = [
# #     "chrome.exe","msedge.exe","firefox.exe",
# #     "code.exe","python.exe","cmd.exe"
# # ]

# # def get_score(name):

# #     lname = name.lower()

# #     # 🔴 Remote tools (highest risk)
# #     for tool in REMOTE_TOOLS:
# #         if tool in lname:
# #             return 15, "Remote Tool"

# #     # 🟢 System processes (very safe)
# #     if lname in SYSTEM_PROCESSES:
# #         return 95, "System"

# #     # 🟡 Trusted apps
# #     if lname in TRUSTED_APPS:
# #         return 80, "Trusted App"

# #     # 🟠 Unknown apps
# #     return 50, "Unknown"


# # def run_scan():
# #     results = []

# #     for proc in psutil.process_iter(['pid','name']):
# #         try:
# #             name = proc.info['name']
# #             if not name:
# #                 continue

# #             cpu = proc.cpu_percent(interval=0.1)

# #             score, reason = get_score(name)

# #             results.append({
# #                 "name": name,
# #                 "pid": proc.info['pid'],
# #                 "cpu": round(cpu,1),
# #                 "score": score,
# #                 "reason": reason
# #             })

# #         except:
# #             continue

# #     # 🔥 SORT → lowest score (danger) top
# #     results.sort(key=lambda x: x['score'])

# #     return results










# import psutil

# REMOTE_TOOLS = ["anydesk","teamviewer","rustdesk","mstsc"]

# SYSTEM_PROCESSES = [
#     "system","system idle process","svchost.exe","lsass.exe",
#     "wininit.exe","csrss.exe","services.exe","explorer.exe"
# ]

# def get_score(name):

#     lname = name.lower()

#     if any(tool in lname for tool in REMOTE_TOOLS):
#         return 15, "Remote Tool"

#     if lname in SYSTEM_PROCESSES:
#         return 95, "System"

#     return 60, "Normal"


# def run_scan():
#     results = []

#     # 🔥 FAST (no interval lag)
#     for proc in psutil.process_iter(['pid','name','cpu_percent']):
#         try:
#             name = proc.info['name']
#             if not name:
#                 continue

#             cpu = proc.info['cpu_percent']  # ⚡ instant

#             score, reason = get_score(name)

#             results.append({
#                 "name": name,
#                 "pid": proc.info['pid'],
#                 "cpu": cpu,
#                 "score": score,
#                 "reason": reason
#             })

#         except:
#             continue

#     results.sort(key=lambda x: x['score'])
#     return results




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