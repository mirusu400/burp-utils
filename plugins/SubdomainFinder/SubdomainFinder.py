from burp import IBurpExtender, IProxyListener, ITab
from javax.swing import JPanel, JScrollPane, JTextArea, JLabel, JTextField, JButton
from java.awt import event
import re


class BurpExtender(IBurpExtender, IProxyListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._all_subs = set()  # all found subdomains
        self._filtered_subs = set()  # filtered subdomains

        # default extension list and endswith list
        self._extensions = [".html", ".do", ".jsp", ".php", ".asp", ".js"]
        self._endswiths = [".example.com", ".test.com"]

        # Panel for UI
        self._panel = JPanel()
        self._panel.setLayout(None)

        # Extension filter UI
        self._label_ext = JLabel("Extension filter (comma separated, e.g. .html,.php):")
        self._label_ext.setBounds(10, 10, 330, 25)
        self._panel.add(self._label_ext)

        self._textField_ext = JTextField(",".join(self._extensions))
        self._textField_ext.setBounds(340, 10, 250, 25)
        self._panel.add(self._textField_ext)

        self._button_ext = JButton("Apply Extensions")
        self._button_ext.setBounds(600, 10, 140, 25)
        self._button_ext.addActionListener(self.ApplyExtensionListener(self))
        self._panel.add(self._button_ext)

        # Endswith filter UI
        self._label_end = JLabel(
            "Subdomain endswith filter (comma separated, e.g. .example.com,.test.com):"
        )
        self._label_end.setBounds(10, 45, 460, 25)
        self._panel.add(self._label_end)

        self._textField_end = JTextField(",".join(self._endswiths))
        self._textField_end.setBounds(470, 45, 180, 25)
        self._panel.add(self._textField_end)

        self._button_end = JButton("Apply Endswith")
        self._button_end.setBounds(660, 45, 120, 25)
        self._button_end.addActionListener(self.ApplyEndswithListener(self))
        self._panel.add(self._button_end)

        # Text area for subdomain log
        self._textArea = JTextArea()
        self._scroll = JScrollPane(self._textArea)
        self._scroll.setBounds(10, 80, 770, 410)
        self._panel.add(self._scroll)

        callbacks.addSuiteTab(self)
        callbacks.setExtensionName("SubdomainFinder [miru-verified]")
        callbacks.registerProxyListener(self)
        return

    # ITab - Tab name
    def getTabCaption(self):
        return "SubdomainFinder"

    # ITab - Tab UI component
    def getUiComponent(self):
        return self._panel

    # Extension filter apply button action
    class ApplyExtensionListener(event.ActionListener):
        def __init__(self, outer):
            self.outer = outer

        def actionPerformed(self, e):
            value = self.outer._textField_ext.getText().strip()
            # ensure each starts with . and no extra spaces
            items = [
                ("." + v.strip().lstrip(".")) for v in value.split(",") if v.strip()
            ]
            if items:
                self.outer._extensions = items

    # Endswith filter apply button action
    class ApplyEndswithListener(event.ActionListener):
        def __init__(self, outer):
            self.outer = outer

        def actionPerformed(self, e):
            value = self.outer._textField_end.getText().strip()
            # ensure each starts with . and no extra spaces
            items = [
                ("." + v.strip().lstrip(".")) for v in value.split(",") if v.strip()
            ]
            if items:
                self.outer._endswiths = items
                self.outer._updateTextArea()

    # Proxy message handler
    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest:
            # analyze URL
            request_info = self._helpers.analyzeRequest(message.getMessageInfo())
            url = request_info.getUrl().toString()
            # only process if extension filter matches
            if any(url.endswith(ext) for ext in self._extensions):
                resp_bytes = message.getMessageInfo().getResponse()
                if resp_bytes is not None:
                    resp_str = self._helpers.bytesToString(resp_bytes)
                    # regex for subdomain extraction
                    pattern = r"(?<![a-zA-Z0-9-\.])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})(?![a-zA-Z0-9-\.])"
                    found = set(re.findall(pattern, resp_str))
                    # only new subdomains
                    new_subs = found - self._all_subs
                    if new_subs:
                        self._all_subs.update(new_subs)
                        self._updateTextArea()

    # Update subdomain text area, filtered by endswith filter
    def _updateTextArea(self):
        filtered = [
            s
            for s in self._all_subs
            if any(s.strip().endswith(e.strip()) for e in self._endswiths)
        ]
        self._filtered_subs = set(filtered)
        self._textArea.setText("\n".join(sorted(self._filtered_subs)))
