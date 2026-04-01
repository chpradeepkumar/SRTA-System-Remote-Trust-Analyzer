import os
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
bat_file = os.path.join(BASE_DIR, "start_srta.bat")

subprocess.Popen(["cmd", "/c", bat_file])
