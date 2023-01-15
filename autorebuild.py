#!/usr/bin/env python3
import subprocess
import os
import requests
import sys
import traceback
import glob

SRGFWLIST_ID = os.environ.get("SRGFWLIST_ID")

try:
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    subprocess.check_call(["git", "reset", "--hard"])
    subprocess.check_call(["git", "config", "user.name", "Autorebuilder"])
    subprocess.check_call(["git", "config", "user.email", "autorebuilder@auto.sh"])
    subprocess.check_call(["git", "pull", "--rebase"])
    subprocess.check_call([sys.executable, "gensrrules.py"])
    status_msg = subprocess.check_output(["git", "status"], encoding="utf-8")
    if "Changes not staged for commit" in status_msg:
        subprocess.check_call(["git", "add"] + glob.glob("fullrules.*"))
        subprocess.check_call(["git", "commit", "-m", "Rebuild full rules"])
        subprocess.check_call(["git", "push"])
        if SRGFWLIST_ID:
            print("Sending notification to", SRGFWLIST_ID, file=sys.stderr)
            requests.post(
                "https://ntfy.sh/" + SRGFWLIST_ID,
                data="srgfwlist updated",
            )
except:
    if SRGFWLIST_ID:
        print("Sending notification to", SRGFWLIST_ID, file=sys.stderr)
        requests.post(
            "https://ntfy.sh/" + SRGFWLIST_ID,
            data="Error: " + traceback.format_exc(),
        )
