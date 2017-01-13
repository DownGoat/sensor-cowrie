import os
import time
import ujson
import requests

__version__ = 0.1

NIKKI_DOMAIN = "http://localhost:8000"


# Settings for cowrie ssh honeypot
CR_LOG_DIR = "C:\\Users\\puse\\Desktop\\aika\\log"


filename = os.path.join(CR_LOG_DIR, "cowrie.json.2017_1_11")

sessions = dict()
login_attempts = []

class FileReader():
    """
    This class is used as a interface to read the log file in a tail like fashion.
    It uses the inode number to check if the log file has been rotated.
    """
    log_file = open(os.path.join(CR_LOG_DIR, filename), "r")
    log_ino = os.fstat(log_file.fileno()).st_ino

    def readlines(self):
        lines = []
        line = self.log_file.readline()
        while line:
            lines.append(line)
            line = self.log_file.readline()

        if os.stat(os.path.join(CR_LOG_DIR, filename)).st_ino != self.log_ino:
            try:
                self.log_file.close()
                self.log_file = open(os.path.join(CR_LOG_DIR, filename), "r")
                self.log_ino = os.fstat(self.log_file.fileno()).st_ino
            except IOError:
                pass

        return lines


def send_session(session):
    # The data found with these keys are not needed by Nikki, so let's just delete them to save bandwidth.
    wanted_keys = ["encCS", "kexAlgs", "keyAlgs", "macCS", "sensor", "session", "src_ip", "src_port", "timestamp", "version"]
    copy = dict(session)

    post_data = {
        "model": "cowrie.SSHSession",
        "fields": {},
    }

    for key in wanted_keys:
        post_data["fields"][key] = session.get(key, None)

    try:
        r = requests.post(NIKKI_DOMAIN + "/cowrie/session", ujson.dumps([post_data]))
        response_json = ujson.loads(r.text)
    except Exception:
        print("[FAIL] SSHSession - Nikki is not responding.")
        return copy

    if r.status_code == 200 or response_json.get("success", False):
        print("[OK] {0} - {1}".format(session["session"], session["src_ip"]))
    else:
        print("[FAIL] {0} - {1}: {2}".format(session["session"], session["src_ip"], response_json["msg"]))

    copy["sent"] = True
    return copy


def send_login_details(login_details):
    if len(login_details) == 0:
        return []

    try:
        r = requests.post(NIKKI_DOMAIN + "/cowrie/login-details", ujson.dumps(login_details))
        response_json = ujson.loads(r.text)
    except Exception:
        print("[FAIL] LoginDetails - Nikki is not responding.")
        return login_details

    if r.status_code == 200 or response_json.get("success", False):
        print("[OK] LoginDetails - length:{0}".format(len(login_details)))
    else:
        print("[FAIL] LoginDetails - length:{0}".format(len(login_details)))

    return []


def parse_event(event):
    session_id = event.get("session")
    if sessions.get(session_id) is None:
        sessions[session_id] = {
            "success": False,
            "sent": False,
        }

    if event["eventid"] == "cowrie.client.version":
        # Do not want these as arrays
        event["macCS"] = "\n".join(event["macCS"])
        event["kexAlgs"] = "\n".join(event["kexAlgs"])
        event["keyAlgs"] = "\n".join(event["keyAlgs"])
        event["encCS"] = "\n".join(event["encCS"])

    if event["eventid"].startswith("cowrie.login."):
        login_attempts.append({
            "model": "cowrie.LoginDetails",
            "fields":
                {
                    "username": event["username"],
                    "password": event["password"],
                    "association": "SSH:{0}".format(session_id)
                }
        })

        if event["eventid"].startswith("cowrie.login.success"):
            sessions[session_id]["success"] = True

    elif event["eventid"] == "cowrie.session.closed":
        sessions[session_id]["success"] = True

    else:
        sessions[session_id] = {**sessions[session_id], **event}


file_reader = FileReader()
while True:
    lines = file_reader.readlines()

    for line in lines:
        event = ujson.loads(line)
        parse_event(event)

    finished_sessions = []
    for session_id, session in sessions.items():
        if session["success"]:
            sessions[session_id] = send_session(session)
            # Only send 20 sessions for each request.
            login_attempts = login_attempts + send_login_details(login_attempts[:20])

            if sessions[session_id]["sent"]:
                finished_sessions.append(session_id)

    for session_id in finished_sessions:
        del sessions[session_id]

    time.sleep(5)