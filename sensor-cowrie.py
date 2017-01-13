import os
import time
import ujson
import requests

NIKKI_DOMAIN = "http://localhost:8000"


# Settings for cowrie ssh honeypot
CR_LOG_DIR = "C:\\Users\\puse\\Desktop\\log"


filename = os.path.join(CR_LOG_DIR, "log.short.json")

sessions = dict()


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


def save_process(offset, session):
    json = ujson.dumps({"offset": offset, "session": session})
    fd = open("progress.json", "w")
    fd.write(json)
    fd.close()


def load():
    """
    fd = open("progress.json", "r")
    data = fd.read()
    json = ujson.loads(data)

    return json.get("offset"), json.get("session")
    """
    return 0, None


def send_session(session):
    not_needed = ["system", "message", "eventid", "isError", "compCS", "dst_port", "dst_ip", "attempts", "success", "sent"]
    copy = dict(session)
    for key in not_needed:
        del session[key]

    post_data = {
        "model": "cowrie.SSHSession",
        "fields": session,
    }
    r = requests.post(NIKKI_DOMAIN + "/cowrie/event", ujson.dumps([post_data]))
    response_json = ujson.loads(r.text)

    if response_json["success"]:
        print("[OK] {0} - {1}".format(session["session"], session["src_ip"]))
    else:
        print("[FAIL] {0} - {1}: {2}".format(session["session"], session["src_ip"], response_json["msg"]))

    copy["sent"] = True

    return copy


def parse_event(event):
    session_id = event.get("session")
    if sessions.get(session_id) is None:
        sessions[session_id] = {
            "success": False,
            "sent": False,
            "attempts": 1,
        }

    if event["eventid"] == "cowrie.client.version":
        # Do not want these as arrays
        event["macCS"] = "\n".join(event["macCS"])
        event["kexAlgs"] = "\n".join(event["kexAlgs"])
        event["keyAlgs"] = "\n".join(event["keyAlgs"])
        event["encCS"] = "\n".join(event["encCS"])

    if event["eventid"].startswith("cowrie.login."):
        sessions[session_id]["password{0}".format(sessions[session_id]["attempts"])] = event["password"]
        sessions[session_id]["username{0}".format(sessions[session_id]["attempts"])] = event["username"]
        sessions[session_id]["attempts"] += 1

        if sessions[session_id]["attempts"] == 4 or event["eventid"].startswith("cowrie.login.success"):
            sessions[session_id]["success"] = True

    elif event["eventid"] == "cowrie.session.closed":
        sessions[session_id]["success"] = True

    else:
        sessions[session_id] = {**sessions[session_id], **event}


offset, _ = load()
file_reader = FileReader()
while True:
    lines = file_reader.readlines()

    for line in lines:
        event = ujson.loads(line)
        parse_event(event)

    finished_sessions = []
    for session_id, session in sessions.items():
        if session["success"]:
            session[session_id] = send_session(session)

            if session[session_id]["sent"]:
                finished_sessions.append(session_id)

    for session_id in finished_sessions:
        del sessions[session_id]

    #save_process(offset, None)
    time.sleep(5)