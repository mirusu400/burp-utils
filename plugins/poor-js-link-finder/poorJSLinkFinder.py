from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JScrollPane, JTable, JButton, JTextField, JLabel
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout
import re
import threading
import json


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Set extension name
        callbacks.setExtensionName("PoorJSLinkFinder")

        # Register HTTP listener
        callbacks.registerHttpListener(self)

        # Initialize UI
        self.initUI()
        callbacks.addSuiteTab(self)

        # Setup regex patterns
        self.setupPatterns()

        # Store found endpoints
        self.found_endpoints = set()
        self._lock = threading.Lock()

    def setupPatterns(self):
        """Setup regex patterns for endpoint discovery"""

        # 1. Full URLs (http://, https://)
        self.pattern_full_url = re.compile(
            r'(?:"|\'|`)([a-zA-Z]{1,10}://[^"\'`\s<>{}|\[\]\\^]{3,})(?:"|\'|`)'
        )

        # 2. Absolute/relative paths with extensions
        self.pattern_path_ext = re.compile(
            r'(?:"|\'|`)([/]?[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-.]{1,}\.[a-zA-Z]{1,4}(?:\?[^"\'`]*)?(?:#[^"\'`]*)?)(?:"|\'|`)'
        )

        # 3. API endpoints (no extension)
        self.pattern_api = re.compile(
            r'(?:"|\'|`)([/]?(?:api|v\d+|graphql|rest)[/][a-zA-Z0-9_\-/]{2,}(?:\?[^"\'`]*)?(?:#[^"\'`]*)?)(?:"|\'|`)',
            re.IGNORECASE,
        )

        # 4. File endpoints
        self.pattern_files = re.compile(
            r'(?:"|\'|`)([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^"\'`]*)?)(?:"|\'|`)'
        )

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process all HTTP messages"""

        # Only process proxy responses
        if toolFlag != self._callbacks.TOOL_PROXY or messageIsRequest:
            return

        # Check scope
        if not self._callbacks.isInScope(messageInfo.getUrl()):
            return

        # Analyze JavaScript in separate thread
        thread = threading.Thread(target=self.analyzeJavaScript, args=(messageInfo,))
        thread.daemon = True
        thread.start()

    def analyzeJavaScript(self, messageInfo):
        """Analyze JavaScript responses"""

        try:
            response = messageInfo.getResponse()
            if not response:
                return

            response_info = self._helpers.analyzeResponse(response)

            # Check if it's JavaScript
            if not self.isJavaScript(messageInfo, response_info):
                return

            # Extract response body
            body_bytes = response[response_info.getBodyOffset() :]
            body = self._helpers.bytesToString(body_bytes)

            # Extract endpoints
            endpoints = self.extractEndpoints(body, messageInfo.getUrl().toString())

            # Update UI
            if endpoints:
                self.updateUI(endpoints)

        except Exception as e:
            self._callbacks.printError("Analysis error: " + str(e))

    def isJavaScript(self, messageInfo, response_info):
        """Check if response is JavaScript"""

        # Check Content-Type header
        headers = response_info.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type:"):
                content_type = header.lower()
                if any(
                    js_type in content_type
                    for js_type in ["javascript", "application/json", "text/javascript"]
                ):
                    return True

        # Check URL extension
        url = messageInfo.getUrl().toString().lower()
        if re.search(r"\.js(\?|$)", url):
            return True

        return False

    def extractEndpoints(self, js_content, source_url):
        """Extract endpoints from JavaScript content"""

        endpoints = []

        # Search with each pattern
        patterns = [
            ("Full URL", self.pattern_full_url),
            ("Path+Extension", self.pattern_path_ext),
            ("API Endpoint", self.pattern_api),
            ("File", self.pattern_files),
        ]

        for pattern_name, pattern in patterns:
            matches = pattern.findall(js_content)
            for match in matches:
                endpoint = match if isinstance(match, str) else match[0]

                # Deduplicate and filter
                if self.isValidEndpoint(endpoint):
                    with self._lock:
                        if endpoint not in self.found_endpoints:
                            self.found_endpoints.add(endpoint)
                            endpoints.append(
                                {
                                    "endpoint": endpoint,
                                    "type": pattern_name,
                                    "source": source_url,
                                }
                            )

        return endpoints

    def isValidEndpoint(self, endpoint):
        """Check if endpoint is valid"""

        # Filter out too short or long endpoints
        if len(endpoint) < 3 or len(endpoint) > 200:
            return False

        # Exclude common libraries
        exclude_patterns = [
            "jquery",
            "angular",
            "react",
            "vue",
            "bootstrap",
            "google-analytics",
            "gtm",
            "ga.js",
        ]

        endpoint_lower = endpoint.lower()
        for pattern in exclude_patterns:
            if pattern in endpoint_lower:
                return False

        return True

    def updateUI(self, endpoints):
        """Update UI with found endpoints"""

        from javax.swing import SwingUtilities

        def update():
            for endpoint_data in endpoints:
                row = [
                    endpoint_data["endpoint"],
                    endpoint_data["type"],
                    endpoint_data["source"],
                ]
                self.table_model.addRow(row)

            # Update status
            total = self.table_model.getRowCount()
            self.status_label.setText("Found endpoints: " + str(total))

        SwingUtilities.invokeLater(update)

    def initUI(self):
        """Initialize user interface"""

        # Main panel
        self.main_panel = JPanel(BorderLayout())

        # Top control panel
        control_panel = JPanel(FlowLayout())

        # Search field
        control_panel.add(JLabel("Search:"))
        self.search_field = JTextField(20)
        control_panel.add(self.search_field)

        # Buttons
        clear_button = JButton("Clear", actionPerformed=self.clearResults)
        export_button = JButton("Export", actionPerformed=self.exportResults)
        control_panel.add(clear_button)
        control_panel.add(export_button)

        # Results table
        self.table_model = DefaultTableModel(["Endpoint", "Type", "Source URL"], 0)
        self.results_table = JTable(self.table_model)
        self.results_table.setAutoCreateRowSorter(True)

        table_scroll = JScrollPane(self.results_table)

        # Status label
        self.status_label = JLabel("Found endpoints: 0")

        # Layout panels
        self.main_panel.add(control_panel, BorderLayout.NORTH)
        self.main_panel.add(table_scroll, BorderLayout.CENTER)
        self.main_panel.add(self.status_label, BorderLayout.SOUTH)

    def clearResults(self, event):
        """Clear all results"""
        with self._lock:
            self.found_endpoints.clear()
        self.table_model.setRowCount(0)
        self.status_label.setText("Found endpoints: 0")

    def exportResults(self, event):
        """Export results as JSON"""
        try:
            results = []
            for row in range(self.table_model.getRowCount()):
                results.append(
                    {
                        "endpoint": self.table_model.getValueAt(row, 0),
                        "type": self.table_model.getValueAt(row, 1),
                        "source": self.table_model.getValueAt(row, 2),
                    }
                )

            # Output JSON to console
            json_output = json.dumps(results, indent=2)
            self._callbacks.printOutput("=== Found Endpoints ===")
            self._callbacks.printOutput(json_output)

        except Exception as e:
            self._callbacks.printError("Export error: " + str(e))

    # ITab interface implementation
    def getTabCaption(self):
        return "PoorJsLinkFinder"

    def getUiComponent(self):
        return self.main_panel
