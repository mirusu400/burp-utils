# BurpFrida.py (Jython)
from burp import IBurpExtender, ITab
from javax.swing import JPanel, JTextField, JButton, JTextArea, JScrollPane, BoxLayout
from java.awt import FlowLayout
import requests # Jython에 requests 라이브러리가 필요. "pip install requests"로 설치 후 jar 파일로 만들어 로드
import threading

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Frida TCP Interceptor")

        # UI 컴포넌트 생성
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        
        # PID 입력 필드
        pid_panel = JPanel(FlowLayout())
        self.pid_field = JTextField(10)
        self.attach_button = JButton("Attach to PID", actionPerformed=self.attach)
        pid_panel.add(self.pid_field)
        pid_panel.add(self.attach_button)

        # 데이터 표시 영역
        self.data_area = JTextArea(20, 80)
        self.data_area.setLineWrap(True)
        scroll_pane = JScrollPane(self.data_area)

        # 포워드 버튼
        self.forward_button = JButton("Forward", actionPerformed=self.forward)
        
        self.panel.add(pid_panel)
        self.panel.add(scroll_pane)
        self.panel.add(self.forward_button)
        
        callbacks.addSuiteTab(self)
        print("Frida TCP Interceptor extension loaded.")
        return

    def getTabCaption(self):
        return "Frida Interceptor"

    def getUiComponent(self):
        return self.panel

    def attach(self, event):
        pid = self.pid_field.getText()
        print("Attempting to attach to PID: " + pid)
        try:
            requests.post('http://127.0.0.1:8008/attach', json={'pid': pid})
            # 백그라운드 스레드에서 데이터 폴링 시작
            threading.Thread(target=self.poll_for_data).start()
        except Exception as e:
            print("Error attaching: " + str(e))

    def poll_for_data(self):
        print("Polling for intercepted data...")
        while True:
            try:
                res = requests.get('http://127.0.0.1:8008/get_intercepted')
                if res.status_code == 200:
                    payload = res.json().get('payload')
                    self.data_area.setText(payload) # UI에 데이터 표시
                    print("Received data, waiting for user to forward...")
            except Exception as e:
                print("Polling error: " + str(e))
                break

    def forward(self, event):
        modified_payload = self.data_area.getText()
        try:
            requests.post('http://127.0.0.1:8008/forward', json={'payload': modified_payload})
            self.data_area.setText("Forwarded. Waiting for next packet...")
        except Exception as e:
            print("Error forwarding: " + str(e))