# frida_server.py
# 필요 라이브러리: pip install flask frida

from flask import Flask, request, jsonify
import frida
import sys
import threading

app = Flask(__name__)
script = None
frida_session = None

# Frida 스크립트로부터 메시지를 처리할 핸들러
# 이 예제에서는 간단하게 콘솔에 출력하고, Burp로 보낼 데이터를 저장
pending_data = None
event = threading.Event()


def on_message(message, data):
    global pending_data
    if message["type"] == "send":
        print(f"[*] Intercepted from Frida: {message['payload']}")
        pending_data = message["payload"]
        event.set()  # Burp 요청 대기를 해제
    else:
        print(message)


# 프로세스에 Frida를 붙이는 API
@app.route("/attach", methods=["POST"])
def attach_to_process():
    global script, frida_session
    pid = request.json.get("pid")
    if not pid:
        return jsonify({"error": "PID not provided"}), 400

    try:
        print(f"[*] Attaching to PID: {pid}")
        frida_session = frida.attach(int(pid))
        with open("ws_hook_burp_crossplatform.js", "r", encoding="utf-8") as f:
            js_code = f.read()
        script = frida_session.create_script(js_code)
        script.on("message", on_message)
        script.load()
        print("[*] Script loaded successfully.")
        return jsonify({"status": "attached"})
    except Exception as e:
        print(f"[!] Error: {e}")
        return jsonify({"error": str(e)}), 500


# Burp가 데이터를 요청하는 API
@app.route("/get_intercepted", methods=["GET"])
def get_intercepted_data():
    global pending_data
    event.wait()  # Frida 스크립트에서 데이터가 올 때까지 대기
    event.clear()
    return jsonify({"payload": pending_data})


# Burp가 수정한 데이터를 Frida 스크립트로 보내는 API
@app.route("/forward", methods=["POST"])
def forward_data():
    modified_payload = request.json.get("payload")
    if script:
        script.post({"type": "modified_data", "payload": modified_payload})
        return jsonify({"status": "forwarded"})
    return jsonify({"error": "script not loaded"}), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8008)
