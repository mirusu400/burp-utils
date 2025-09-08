package burp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

public class BurpExtender implements IBurpExtender, ITab, IProxyListener, IContextMenuFactory {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    // UI Components
    private JPanel mainPanel;
    private DefaultTableModel tableModel;
    private JTable resultsTable;
    private JTextArea detailsArea;
    private JLabel statusLabel;
    
    // Data
    private List<JSAnalysisResult> results = new ArrayList<>();
    
    // JavaScript 분석을 위한 정규식 패턴들
    private static final Map<String, String> SECRET_PATTERNS = new HashMap<String, String>() {{
        put("Google API Key", "AIza[0-9A-Za-z-_]{35}");
        put("AWS Access Key", "A[SK]IA[0-9A-Z]{16}");
        put("GitHub Token", "ghp_[a-zA-Z0-9]{36}");
        put("JWT Token", "ey[A-Za-z0-9_-]*\\.[A-Za-z0-9._-]*");
        put("Authorization Bearer", "bearer\\s+[a-zA-Z0-9_\\-\\.=:_\\+\\/]{20,}");
        put("Private Key", "-----BEGIN (?:RSA |EC )?PRIVATE KEY-----");
        put("Firebase", "AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}");
        put("Slack Token", "xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}");
    }};
    
    private static final String[] ENDPOINT_PATTERNS = {
        "(?:https?://[^\\s\"'<>]+)",
        "(?:\"|')(/[a-zA-Z0-9._~:/?#\\[\\]@!$&'()*+,;=-]+)(?:\"|')",
        "(?:api|endpoint|url)\\s*[:=]\\s*[\"']([^\"']+)[\"']",
        "fetch\\s*\\(\\s*[\"']([^\"']+)[\"']",
        "\\.(?:get|post|put|delete|patch)\\s*\\(\\s*[\"']([^\"']+)[\"']"
    };

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // 확장 이름 설정
        callbacks.setExtensionName("Poor JS Miner ");
        
        // UI 초기화
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                initializeUI();
            }
        });
        
        // Proxy 리스너 등록
        callbacks.registerProxyListener(this);
        
        // Context 메뉴 등록
        callbacks.registerContextMenuFactory(this);
        
        // 탭 등록
        callbacks.addSuiteTab(this);
        
        stdout.println("Poor JS Miner Edition loaded successfully!");
    }
    
    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        
        // 상단 컨트롤 패널
        JPanel controlPanel = createControlPanel();
        mainPanel.add(controlPanel, BorderLayout.NORTH);
        
        // 메인 분할 패널
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setDividerLocation(400);
        splitPane.setResizeWeight(0.6);
        
        // 상단: 결과 테이블
        JPanel tablePanel = createTablePanel();
        splitPane.setTopComponent(tablePanel);
        
        // 하단: 상세 정보
        JPanel detailsPanel = createDetailsPanel();
        splitPane.setBottomComponent(detailsPanel);
        
        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        // 하단 상태 바
        statusLabel = new JLabel("Ready - Monitoring JavaScript files...");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        mainPanel.add(statusLabel, BorderLayout.SOUTH);
    }
    
    private JPanel createControlPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                clearResults();
            }
        });
        
        JButton exportButton = new JButton("Export Results");
        exportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportResults();
            }
        });
        
        JCheckBox secretsOnlyBox = new JCheckBox("Show Secrets Only");
        secretsOnlyBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                filterResults(secretsOnlyBox.isSelected());
            }
        });
        
        panel.add(clearButton);
        panel.add(exportButton);
        panel.add(new JSeparator(SwingConstants.VERTICAL));
        panel.add(secretsOnlyBox);
        
        return panel;
    }
    
    private JPanel createTablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        String[] columnNames = {"#", "Host", "URL", "Type", "Endpoints", "Secrets", "Timestamp"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0 || columnIndex == 4 || columnIndex == 5) {
                    return Integer.class;
                }
                return String.class;
            }
        };
        
        resultsTable = new JTable(tableModel);
        resultsTable.setAutoCreateRowSorter(true);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        // 컬럼 너비 설정
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(30);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(50);
        
        // 선택 리스너
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                displaySelectedDetails();
            }
        });
        
        JScrollPane scrollPane = new JScrollPane(resultsTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createDetailsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        detailsArea = new JTextArea();
        detailsArea.setEditable(false);
        detailsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        JScrollPane scrollPane = new JScrollPane(detailsArea);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        // 응답만 처리
        if (!messageIsRequest) {
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            analyzeResponse(messageInfo);
        }
    }
    
    private void analyzeResponse(IHttpRequestResponse messageInfo) {
        try {
            IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
            String contentType = getContentType(responseInfo);
            String url = helpers.analyzeRequest(messageInfo).getUrl().toString();
            
            // JavaScript 콘텐츠인지 확인
            if (isJavaScriptContent(contentType, url)) {
                String responseBody = new String(messageInfo.getResponse()).substring(responseInfo.getBodyOffset());
                
                // JavaScript 분석 수행
                JSAnalysisResult result = analyzeJavaScript(responseBody, url);
                
                if (result.hasFindings()) {
                    SwingUtilities.invokeLater(() -> addResult(result));
                    stdout.println(String.format("[JS Miner] Found %d endpoints, %d secrets in %s", 
                        result.getEndpoints().size(), result.getSecrets().size(), url));
                }
            }
        } catch (Exception e) {
            stderr.println("Analysis error: " + e.getMessage());
        }
    }
    
    private String getContentType(IResponseInfo responseInfo) {
        for (String header : responseInfo.getHeaders()) {
            if (header.toLowerCase().startsWith("content-type:")) {
                return header.toLowerCase();
            }
        }
        return "";
    }
    
    private boolean isJavaScriptContent(String contentType, String url) {
        return contentType.contains("javascript") || 
               contentType.contains("json") ||
               url.toLowerCase().endsWith(".js") || 
               url.toLowerCase().endsWith(".json") ||
               url.toLowerCase().contains(".js?");
    }
    
    private JSAnalysisResult analyzeJavaScript(String jsContent, String url) {
        JSAnalysisResult result = new JSAnalysisResult(url);
        
        // 엔드포인트 추출
        Set<String> endpoints = extractEndpoints(jsContent);
        result.setEndpoints(endpoints);
        
        // 시크릿 추출
        Map<String, List<String>> secrets = extractSecrets(jsContent);
        result.setSecrets(secrets);
        
        // 미니파이 여부 확인
        result.setMinified(isMinified(jsContent));
        
        return result;
    }
    
    private Set<String> extractEndpoints(String jsContent) {
        Set<String> endpoints = new HashSet<>();
        
        for (String patternStr : ENDPOINT_PATTERNS) {
            Pattern pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(jsContent);
            
            while (matcher.find()) {
                for (int i = 0; i <= matcher.groupCount(); i++) {
                    String match = matcher.group(i);
                    if (match != null && !match.isEmpty() && isValidEndpoint(match)) {
                        endpoints.add(match);
                    }
                }
            }
        }
        
        return endpoints;
    }
    
    private Map<String, List<String>> extractSecrets(String jsContent) {
        Map<String, List<String>> secrets = new HashMap<>();
        
        for (Map.Entry<String, String> entry : SECRET_PATTERNS.entrySet()) {
            String secretType = entry.getKey();
            String patternStr = entry.getValue();
            
            Pattern pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(jsContent);
            
            List<String> matches = new ArrayList<>();
            while (matcher.find()) {
                matches.add(matcher.group(0));
            }
            
            if (!matches.isEmpty()) {
                secrets.put(secretType, matches);
            }
        }
        
        return secrets;
    }
    
    private boolean isMinified(String jsContent) {
        long totalChars = jsContent.length();
        long newlines = jsContent.chars().filter(ch -> ch == '\n').count();
        long spaces = jsContent.chars().filter(ch -> ch == ' ').count();
        
        return (newlines + spaces) < (totalChars * 0.01);
    }
    
    private boolean isValidEndpoint(String url) {
        String[] excludePatterns = {"jquery", "bootstrap", "google-analytics", "googletagmanager"};
        String lowerUrl = url.toLowerCase();
        
        for (String pattern : excludePatterns) {
            if (lowerUrl.contains(pattern)) {
                return false;
            }
        }
        
        return true;
    }
    
    private void addResult(JSAnalysisResult result) {
        results.add(result);
        
        Object[] rowData = {
            tableModel.getRowCount() + 1,
            result.getHost(),
            result.getUrl(),
            result.isMinified() ? "MIN" : "STD",
            result.getEndpoints().size(),
            result.getSecrets().size(),
            result.getTimestamp()
        };
        
        tableModel.addRow(rowData);
        updateStatus();
        
        // 중요한 발견사항이 있으면 하이라이트
        if (!result.getSecrets().isEmpty()) {
            int lastRow = tableModel.getRowCount() - 1;
            resultsTable.setRowSelectionInterval(lastRow, lastRow);
        }
    }
    
    private void displaySelectedDetails() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow >= 0 && selectedRow < results.size()) {
            JSAnalysisResult result = results.get(selectedRow);
            
            StringBuilder details = new StringBuilder();
            details.append("URL: ").append(result.getUrl()).append("\n");
            details.append("Host: ").append(result.getHost()).append("\n");
            details.append("Analyzed: ").append(result.getTimestamp()).append("\n");
            details.append("Minified: ").append(result.isMinified() ? "Yes" : "No").append("\n\n");
            
            details.append("=== ENDPOINTS ===\n");
            for (String endpoint : result.getEndpoints()) {
                details.append("• ").append(endpoint).append("\n");
            }
            
            details.append("\n=== SECRETS ===\n");
            for (Map.Entry<String, List<String>> entry : result.getSecrets().entrySet()) {
                details.append(entry.getKey()).append(":\n");
                for (String secret : entry.getValue()) {
                    details.append("  • ").append(secret).append("\n");
                }
            }
            
            detailsArea.setText(details.toString());
            detailsArea.setCaretPosition(0);
        }
    }
    
    private void clearResults() {
        results.clear();
        tableModel.setRowCount(0);
        detailsArea.setText("");
        updateStatus();
    }
    
    private void exportResults() {
        StringBuilder export = new StringBuilder();
        export.append("JS Miner Results Export\n");
        export.append("=======================\n\n");
        
        for (JSAnalysisResult result : results) {
            export.append("URL: ").append(result.getUrl()).append("\n");
            export.append("Endpoints: ").append(result.getEndpoints().size()).append("\n");
            export.append("Secrets: ").append(result.getSecrets().size()).append("\n");
            export.append("---\n");
        }
        
        detailsArea.setText(export.toString());
        stdout.println("Results exported to details panel");
    }
    
    private void filterResults(boolean secretsOnly) {
        if (secretsOnly) {
            TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
            sorter.setRowFilter(RowFilter.regexFilter("^(?!.*\\b0\\b).*", 5)); // 시크릿이 0이 아닌 행만
            resultsTable.setRowSorter(sorter);
        } else {
            resultsTable.setRowSorter(new TableRowSorter<>(tableModel));
        }
    }
    
    private void updateStatus() {
        int totalFiles = results.size();
        int totalEndpoints = results.stream().mapToInt(r -> r.getEndpoints().size()).sum();
        int totalSecrets = results.stream().mapToInt(r -> r.getSecrets().size()).sum();
        
        statusLabel.setText(String.format("Files: %d | Endpoints: %d | Secrets: %d", 
            totalFiles, totalEndpoints, totalSecrets));
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_PROXY_HISTORY ||
            invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
            
            JMenuItem analyzeItem = new JMenuItem("Analyze with JS Miner");
            analyzeItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    for (IHttpRequestResponse message : invocation.getSelectedMessages()) {
                        analyzeResponse(message);
                    }
                }
            });
            menuItems.add(analyzeItem);
        }
        
        return menuItems;
    }

    @Override
    public String getTabCaption() {
        return "JS Miner";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
    
    // 결과 저장을 위한 내부 클래스
    private static class JSAnalysisResult {
        private final String url;
        private final String host;
        private final String timestamp;
        private Set<String> endpoints = new HashSet<>();
        private Map<String, List<String>> secrets = new HashMap<>();
        private boolean minified = false;
        
        public JSAnalysisResult(String url) {
            this.url = url;
            this.host = extractHost(url);
            this.timestamp = new Date().toString();
        }
        
        private String extractHost(String url) {
            try {
                return new java.net.URL(url).getHost();
            } catch (Exception e) {
                return "unknown";
            }
        }
        
        public boolean hasFindings() {
            return !endpoints.isEmpty() || !secrets.isEmpty();
        }
        
        // Getters and setters
        public String getUrl() { return url; }
        public String getHost() { return host; }
        public String getTimestamp() { return timestamp; }
        public Set<String> getEndpoints() { return endpoints; }
        public void setEndpoints(Set<String> endpoints) { this.endpoints = endpoints; }
        public Map<String, List<String>> getSecrets() { return secrets; }
        public void setSecrets(Map<String, List<String>> secrets) { this.secrets = secrets; }
        public boolean isMinified() { return minified; }
        public void setMinified(boolean minified) { this.minified = minified; }
    }
}