package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;


import burp.api.montoya.core.Range;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.intruder.HttpRequestTemplate;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;
import java.awt.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

public class BurpExtender implements BurpExtension, ProxyResponseHandler, HttpHandler, ContextMenuItemsProvider, AuditInsertionPointProvider {

    private MontoyaApi api;
    
    // Data Models
    private final List<ReflectedRequest> allRequests = new CopyOnWriteArrayList<>();
    private final List<ReflectedRequest> displayedRequests = new CopyOnWriteArrayList<>();

    
    // Active Scan Targeting
    private final Set<Integer> targetedForParameterScan = Collections.synchronizedSet(new HashSet<>());
    
    // Filtering State
    private final Set<Short> knownStatusCodes = new HashSet<>();
    private final Set<Short> hiddenStatusCodes = new HashSet<>();
    private final Set<String> knownContentTypes = new HashSet<>();
    private final Set<String> hiddenContentTypes = new HashSet<>();
    private boolean deduplicateEnabled = false;
    private final Set<String> enabledTools = Collections.synchronizedSet(new HashSet<>());

    // UI Components
    private RequestsTable requestsTable;
    private RequestsTableModel requestsTableModel;
    private JButton filterButton;
    private JButton statusFilterButton;
    private JButton configButton;
    private JButton deduplicateButton;
    
    private ParamsTable paramsTable;
    private ParamsTableModel paramsTableModel;
    
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    
    private static final String EXTENSION_NAME = "Reflection+";
    private static final int MIN_PARAM_LENGTH = 4;
    private static final Color LABEL_COLOR = new Color(229, 137, 0);
    private static final int MAX_ENTRIES = 1000;
    private static final int PARAMS_PANEL_WIDTH = 350;
    private static final int[] COLUMN_WIDTHS = {30, 200, 80, 450, 50, 80, 120, 150, 2, 90, 90, 60, 60};
    private int entryCounter = 0;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(EXTENSION_NAME);
        
        // Initialize default known types
        knownContentTypes.add("text/html");
        knownContentTypes.add("application/json");
        knownContentTypes.add("text/javascript");
        
        // Initialize enabled tools
        enabledTools.add("Proxy");
        enabledTools.add("Repeater");
        
        SwingUtilities.invokeLater(() -> {
            JSplitPane splitPane = createMainPanel();
            api.userInterface().registerSuiteTab(EXTENSION_NAME, splitPane);
        });

        api.proxy().registerResponseHandler(this);
        api.http().registerHttpHandler(this);
        api.userInterface().registerContextMenuItemsProvider(this);
        
        api.scanner().registerInsertionPointProvider(this);
        api.logging().logToOutput("Reflection+ v1.0 loaded.");
    }

    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse requestResponse) {

        if (targetedForParameterScan.isEmpty()) return Collections.emptyList();

        ReflectedRequest matchedRequest = null;
        for (ReflectedRequest req : allRequests) {
            if (targetedForParameterScan.contains(req.id)) {

                 if (req.url.equals(requestResponse.request().url()) && req.method.equals(requestResponse.request().method())) {
                     matchedRequest = req;
                     break;
                 }
            }
        }

        if (matchedRequest != null) {
            List<AuditInsertionPoint> points = new ArrayList<>();
            for (ReflectedParam param : matchedRequest.params) {
                if (param.requestValueRange != null) {
                    points.add(AuditInsertionPoint.auditInsertionPoint(
                        param.name, 
                        matchedRequest.requestResponse.request(), 
                        param.requestValueRange.startIndexInclusive(), 
                        param.requestValueRange.endIndexExclusive()
                    ));
                }
            }
            return points;
        }

        return Collections.emptyList();
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(burp.api.montoya.proxy.http.InterceptedResponse interceptedResponse) {
        if (!enabledTools.contains("Proxy")) return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        if (interceptedResponse.body().length() == 0) return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        
        HttpRequestResponse reqRes = HttpRequestResponse.httpRequestResponse(
            interceptedResponse.initiatingRequest(), 
            interceptedResponse
        );
        processResponse(reqRes, "Proxy");
        
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(burp.api.montoya.proxy.http.InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    // HttpHandler Implementation for Scanner/Other tools
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(burp.api.montoya.http.handler.HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(burp.api.montoya.http.handler.HttpResponseReceived responseReceived) {
        String toolName = responseReceived.toolSource().toolType().toolName();
        if (enabledTools.contains(toolName)) {
             HttpRequestResponse reqRes = HttpRequestResponse.httpRequestResponse(
                responseReceived.initiatingRequest(),
                responseReceived
            );
            processResponse(reqRes, toolName);
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void processResponse(HttpRequestResponse response, String toolName) {
        if (allRequests.size() >= MAX_ENTRIES) return;

        HttpRequest request = response.request();
        if (!api.scope().isInScope(request.url())) return;
        if (!isInterestingContentType(response.response())) return;

        List<ParsedHttpParameter> params = request.parameters();
        if (params.isEmpty()) return;

        String responseBodyStr = response.response().bodyToString();
        String fullUrl = request.url();
        String url = fullUrl;
        try {
            java.net.URL u = new java.net.URL(fullUrl);
            url = u.getFile(); // returns path + query
            if (url.isEmpty()) url = "/";
        } catch (Exception e) {
            // keep fullUrl if parsing fails
        }
        
        List<ReflectedParam> foundParams = new ArrayList<>();
        
        for (ParsedHttpParameter param : params) {
            if (param.type() == HttpParameterType.COOKIE) continue;
            
            String value = param.value();
            if (value == null || value.length() < MIN_PARAM_LENGTH) continue;


            List<Range> responseRanges = new ArrayList<>();
            String reflectedValue = findReflections(responseBodyStr, value, responseRanges);

            if (!reflectedValue.isEmpty()) {

                
                // Adjust ranges for header offset
                int headerLen = response.response().bodyOffset();
                List<Range> adjustedResponseRanges = new ArrayList<>();
                for (Range r : responseRanges) {
                    adjustedResponseRanges.add(Range.range(r.startIndexInclusive() + headerLen, r.endIndexExclusive() + headerLen));
                }
                
                foundParams.add(new ReflectedParam(
                    param.name(),
                    value,
                    reflectedValue,
                    adjustedResponseRanges,
                    findValueRange(request, value)
                ));
            }
        }
        
        if (!foundParams.isEmpty()) {
            synchronized (this) {
                entryCounter++;
                String contentType = extractContentType(response.response());
                short statusCode = response.response().statusCode();
                
                ReflectedRequest entry = new ReflectedRequest(
                    entryCounter,
                    response,
                    request.httpService().host(),
                    request.method(),
                    url,
                    statusCode,
                    toolName,
                    response.response().body().length(),
                    contentType,
                    foundParams
                );
                
                allRequests.add(entry);
                
                if (!contentType.isEmpty()) knownContentTypes.add(contentType);
                knownStatusCodes.add(statusCode);
                
                refreshTable();
            }
        }
    }
    
    private void refreshTable() {
        SwingUtilities.invokeLater(() -> {
            displayedRequests.clear();
            Set<String> seenEntries = deduplicateEnabled ? new HashSet<>() : null;
            
            for (ReflectedRequest entry : allRequests) {
                if (hiddenContentTypes.contains(entry.contentType) || hiddenStatusCodes.contains(entry.statusCode)) {
                    continue;
                }
                
                if (deduplicateEnabled) {
                    String uniqueKey = entry.host + "|" + entry.url + "|" + entry.statusCode;
                    if (!seenEntries.add(uniqueKey)) continue;
                }
                
                displayedRequests.add(entry);
            }
            requestsTableModel.fireTableDataChanged();
        });
    }

    private String findReflections(String responseBody, String paramValue, List<Range> ranges) {
        StringBuilder result = new StringBuilder();
        boolean found = false;
        if (findAndMark(responseBody, paramValue, ranges)) {
            result.append(paramValue);
            found = true;
        }
        try {
            String decoded = URLDecoder.decode(paramValue, StandardCharsets.UTF_8.name());
            if (!decoded.equals(paramValue) && findAndMark(responseBody, decoded, ranges)) {
                if (found) result.append(", ");
                result.append(decoded);
            }
        } catch (Exception ignored) {
            // Ignore decoding errors
        }
        return result.toString();
    }

    private boolean findAndMark(String haystack, String needle, List<Range> ranges) {
        boolean found = false;
        int index = 0;
        int needleLen = needle.length();
        if (needleLen == 0) return false;

        while ((index = haystack.indexOf(needle, index)) != -1) {
            ranges.add(Range.range(index, index + needleLen));
            index += needleLen;
            found = true;
        }
        return found;
    }

    private boolean isInterestingContentType(HttpResponse response) {
        String ct = extractContentType(response).toLowerCase();
        return ct.contains("html") || ct.contains("json") || ct.contains("xml") || ct.contains("javascript");
    }
    
    private Range findValueRange(HttpRequest request, String value) {
        String reqStr = request.toString();
        int start = reqStr.indexOf(value);
        if (start != -1) {
            return Range.range(start, start + value.length());
        }
        return null;
    }

    private String extractContentType(HttpResponse response) {
        if (response.hasHeader("Content-Type")) {
            String ct = response.headerValue("Content-Type");
            int semi = ct.indexOf(';');
            if (semi != -1) return ct.substring(0, semi).trim();
            return ct;
        }
        return "";
    }

    // --- UI Construction ---

    private JSplitPane createMainPanel() {
        createFilterButtons();
        
        // 1. Top Table (Requests)
        requestsTableModel = new RequestsTableModel();
        requestsTable = new RequestsTable(requestsTableModel);
        
        // Apply Legacy Column Widths
        requestsTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        for (int i = 0; i < COLUMN_WIDTHS.length; i++) {
            if (i < requestsTable.getColumnCount()) {
                requestsTable.getColumnModel().getColumn(i).setPreferredWidth(COLUMN_WIDTHS[i]);
            }
        }
        
        configureSpecialColumns(requestsTable);
        JScrollPane requestsScrollPane = new JScrollPane(requestsTable);

        // 2. Bottom Left Table (Params)
        paramsTableModel = new ParamsTableModel();
        paramsTable = new ParamsTable(paramsTableModel);
        JScrollPane paramsScrollPane = new JScrollPane(paramsTable);

        // 3. Bottom Right Editors
        requestViewer = api.userInterface().createHttpRequestEditor();
        responseViewer = api.userInterface().createHttpResponseEditor();
        
        JPanel requestPanel = createEditorPanel("Request", requestViewer.uiComponent());
        JPanel responsePanel = createEditorPanel("Response", responseViewer.uiComponent());
        
        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
        editorSplit.setResizeWeight(0.5);

        // 4. Bottom Split (Params | Editors)
        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, paramsScrollPane, editorSplit);
        bottomSplit.setDividerLocation(PARAMS_PANEL_WIDTH); 
        bottomSplit.setResizeWeight(0.0); // Keep params panel fixed size

        // 5. Main Split (Requests / Bottom)
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, requestsScrollPane, bottomSplit);
        mainSplit.setResizeWeight(0.4);
        
        return mainSplit;
    }

    private JPanel createEditorPanel(String title, Component component) {
        JPanel panel = new JPanel(new BorderLayout());
        JLabel label = new JLabel(title, SwingConstants.LEFT);
        label.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 0));
        label.setForeground(LABEL_COLOR);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 14f));
        panel.add(label, BorderLayout.NORTH);
        panel.add(component, BorderLayout.CENTER);
        return panel;
    }
    
    private void createFilterButtons() {
        filterButton = createStyledButton("Filter");
        statusFilterButton = createStyledButton("Filter Status");
        configButton = createStyledButton("Options");
        deduplicateButton = createStyledButton("Deduplicate");
        deduplicateButton.addActionListener(e -> toggleDeduplicate());
    }
    
    private JButton createStyledButton(String text) {
        JButton button = new JButton(text);
        button.setFont(button.getFont().deriveFont(Font.BOLD));
        button.setBorder(new javax.swing.border.LineBorder(Color.GRAY, 2, true));
        button.setFocusPainted(false);
        return button;
    }
    
    private void toggleDeduplicate() {
        deduplicateEnabled = !deduplicateEnabled;
        deduplicateButton.setText(deduplicateEnabled ? "Show All" : "Deduplicate");
        refreshTable();
    }
    
    private void configureSpecialColumns(JTable table) {
        // Separator column renderer
        javax.swing.table.TableCellRenderer separatorRenderer = (t, v, sel, foc, row, col) -> {
            JPanel p = new JPanel();
            p.setBackground(Color.GRAY);
            return p;
        };
        
        table.getColumnModel().getColumn(8).setHeaderRenderer((t, v, sel, foc, row, col) -> {
            JPanel p = new JPanel();
            p.setBackground(Color.GRAY);
            p.setPreferredSize(new Dimension(2, t.getTableHeader().getHeight()));
            return p;
        });
        table.getColumnModel().getColumn(8).setCellRenderer(separatorRenderer);
        
        // Button column renderers
        javax.swing.table.TableCellRenderer emptyRenderer = (t, v, sel, foc, row, col) -> new JPanel();
        
        table.getColumnModel().getColumn(9).setHeaderRenderer((t, v, sel, foc, row, col) -> deduplicateButton);
        table.getColumnModel().getColumn(10).setHeaderRenderer((t, v, sel, foc, row, col) -> statusFilterButton);
        table.getColumnModel().getColumn(11).setHeaderRenderer((t, v, sel, foc, row, col) -> filterButton);
        table.getColumnModel().getColumn(12).setHeaderRenderer((t, v, sel, foc, row, col) -> configButton);
        
        for (int i = 9; i <= 12; i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(emptyRenderer);
        }
        
        // Header Click Listener
        table.getTableHeader().addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                int column = table.getTableHeader().columnAtPoint(e.getPoint());
                if (column < 0) return;
                
                int modelColumn = table.convertColumnIndexToModel(column);
                if (modelColumn == 9) {
                    toggleDeduplicate();
                    table.getTableHeader().repaint();
                } else if (modelColumn == 10) {
                    showStatusFilterMenu(table.getTableHeader(), e.getX());
                } else if (modelColumn == 11) {
                    showContentTypeFilterMenu(table.getTableHeader(), e.getX());
                } else if (modelColumn == 12) {
                    showConfigMenu(table.getTableHeader(), e.getX());
                }
            }
        });
    }
    
    private void showConfigMenu(Component invoker, int x) {
        JPopupMenu menu = new JPopupMenu();
        String[] tools = {"Proxy", "Scanner", "Intruder", "Repeater"};
        
        for (String tool : tools) {
            JCheckBoxMenuItem item = new JCheckBoxMenuItem(tool);
            item.setSelected(enabledTools.contains(tool));
            item.addActionListener(e -> {
                if (item.isSelected()) enabledTools.add(tool);
                else enabledTools.remove(tool);
            });
            menu.add(item);
        }
        menu.show(invoker, x, invoker.getHeight());
    }
    
    private void showStatusFilterMenu(Component invoker, int x) {
        JPopupMenu menu = new JPopupMenu();
        addBoldMenuItem(menu, "Select All", () -> { hiddenStatusCodes.clear(); refreshTable(); });
        addBoldMenuItem(menu, "Deselect All", () -> { hiddenStatusCodes.addAll(knownStatusCodes); refreshTable(); });
        menu.add(new JSeparator());
        
        List<Short> sortedCodes = new ArrayList<>(knownStatusCodes);
        Collections.sort(sortedCodes);
        
        for (Short code : sortedCodes) {
            JCheckBoxMenuItem item = new JCheckBoxMenuItem(code.toString());
            item.setSelected(!hiddenStatusCodes.contains(code));
            item.addActionListener(e -> {
                if (item.isSelected()) hiddenStatusCodes.remove(code);
                else hiddenStatusCodes.add(code);
                refreshTable();
            });
            menu.add(item);
        }
        menu.show(invoker, x, invoker.getHeight());
    }
    
    private void showContentTypeFilterMenu(Component invoker, int x) {
        JPopupMenu menu = new JPopupMenu();
        addBoldMenuItem(menu, "Select All", () -> { hiddenContentTypes.clear(); refreshTable(); });
        addBoldMenuItem(menu, "Deselect All", () -> { hiddenContentTypes.addAll(knownContentTypes); refreshTable(); });
        menu.add(new JSeparator());
        
        List<String> sortedTypes = new ArrayList<>(knownContentTypes);
        Collections.sort(sortedTypes);
        
        for (String type : sortedTypes) {
            JCheckBoxMenuItem item = new JCheckBoxMenuItem(type);
            item.setSelected(!hiddenContentTypes.contains(type));
            item.addActionListener(e -> {
                if (item.isSelected()) hiddenContentTypes.remove(type);
                else hiddenContentTypes.add(type);
                refreshTable();
            });
            menu.add(item);
        }
        menu.show(invoker, x, invoker.getHeight());
    }
    
    private void addBoldMenuItem(JPopupMenu menu, String text, Runnable action) {
        JMenuItem item = new JMenuItem(text);
        item.setFont(item.getFont().deriveFont(Font.BOLD));
        item.addActionListener(e -> action.run());
        menu.add(item);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            JMenuItem item = new JMenuItem("Send to Reflection+");
            item.addActionListener(e -> {
                burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse editorReqRes = event.messageEditorRequestResponse().get();
                HttpRequestResponse reqRes = editorReqRes.requestResponse();
                new Thread(() -> processResponse(reqRes, "Manual")).start();
            });
            return Collections.singletonList(item);
        }
        return Collections.emptyList();
    }

    // --- Data Classes ---

    private static class ReflectedRequest {
        final int id;
        final HttpRequestResponse requestResponse;
        final String host;
        final String method;
        final String url;
        final short statusCode;
        final String tool;
        final int contentLength;
        final String contentType;
        final List<ReflectedParam> params;

        ReflectedRequest(int id, HttpRequestResponse requestResponse, String host, String method, String url, 
                         short statusCode, String tool, int contentLength, String contentType, List<ReflectedParam> params) {
            this.id = id;
            this.requestResponse = requestResponse;
            this.host = host;
            this.method = method;
            this.url = url;
            this.statusCode = statusCode;
            this.tool = tool;
            this.contentLength = contentLength;
            this.contentType = contentType;
            this.params = params;
        }
    }

    private static class ReflectedParam {
        final String name;
        final String value;
        final String reflectedValue;
        final List<Range> responseRanges;
        final Range requestValueRange;

        ReflectedParam(String name, String value, String reflectedValue, List<Range> responseRanges, Range requestValueRange) {
            this.name = name;
            this.value = value;
            this.reflectedValue = reflectedValue;
            this.responseRanges = responseRanges;
            this.requestValueRange = requestValueRange;
        }
    }

    // --- Tables ---

    private class RequestsTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "#", "Host", "Method", "URL", "Status", "Tool", "Content Length", "Content Type",
            "|", "Deduplicate", "Filter Status", "Filter", "Reflected Check"
        };

        @Override
        public int getRowCount() { return displayedRequests.size(); }
        @Override
        public int getColumnCount() { return COLS.length; }
        @Override
        public String getColumnName(int col) { return COLS[col]; }
        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0 || columnIndex == 4 || columnIndex == 6) return Integer.class;
            return String.class;
        }

        @Override
        public Object getValueAt(int row, int col) {
            if (row >= displayedRequests.size()) return "";
            ReflectedRequest req = displayedRequests.get(row);
            switch (col) {
                case 0: return req.id;
                case 1: return req.host;
                case 2: return req.method;
                case 3: return req.url;
                case 4: return (int) req.statusCode;
                case 5: return req.tool;
                case 6: return req.contentLength;
                case 7: return req.contentType;
                default: return ""; // Buttons and separators
            }
        }
    }

    private class RequestsTable extends JTable {
        public RequestsTable(TableModel model) {
            super(model);
            setAutoCreateRowSorter(true);
            setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            getTableHeader().setFont(getTableHeader().getFont().deriveFont(java.awt.Font.BOLD));
            
            // Context Menu
            JPopupMenu popupMenu = new JPopupMenu();
            JMenuItem scanItem = new JMenuItem("Active scan whole request");
            JMenuItem scanParamsItem = new JMenuItem("Active scan reflected parameters");
            JMenuItem xssScanItem = new JMenuItem("Active XSS scan whole request");
            JMenuItem xssScanParamsItem = new JMenuItem("Active XSS scan reflected parameters");
            JMenuItem intruderItem = new JMenuItem("Send request to Intruder");
            JMenuItem repeaterItem = new JMenuItem("Send request to Repeater");
            JMenuItem copyUrlItem = new JMenuItem("Copy URL");
            JMenuItem deleteItem = new JMenuItem("Delete item");
            JMenuItem clearItem = new JMenuItem("Clear list");
            
            scanItem.addActionListener(e -> startScan(false, false));
            scanParamsItem.addActionListener(e -> startScan(false, true));
            xssScanItem.addActionListener(e -> startScan(true, false));
            xssScanParamsItem.addActionListener(e -> startScan(true, true));
            
            intruderItem.addActionListener(e -> {
                ReflectedRequest req = getSelectedRequest();
                if (req != null) {
                    List<Range> ranges = new ArrayList<>();
                    for (ReflectedParam p : req.params) {
                        if (p.requestValueRange != null) ranges.add(p.requestValueRange);
                    }
                    if (ranges.isEmpty()) {
                        api.intruder().sendToIntruder(req.requestResponse.request());
                    } else {
                        // Send with markers
                        api.intruder().sendToIntruder(req.requestResponse.httpService(), HttpRequestTemplate.httpRequestTemplate(req.requestResponse.request(), ranges));
                    }
                }
            });
            
            repeaterItem.addActionListener(e -> {
                ReflectedRequest req = getSelectedRequest();
                if (req != null) api.repeater().sendToRepeater(req.requestResponse.request());
            });
            
            copyUrlItem.addActionListener(e -> {
                ReflectedRequest req = getSelectedRequest();
                if (req != null) {
                    String url = req.url;
                    java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(url);
                    java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
                }
            });
            
            deleteItem.addActionListener(e -> {
                int row = getSelectedRow();
                if (row != -1) {
                    int modelRow = convertRowIndexToModel(row);
                    ReflectedRequest req = displayedRequests.get(modelRow);
                    allRequests.remove(req);
                    refreshTable();
                }
            });
            
            clearItem.addActionListener(e -> {
                allRequests.clear();
                knownStatusCodes.clear();
                knownContentTypes.clear();
                // Re-add defaults
                knownContentTypes.add("text/html");
                knownContentTypes.add("application/json");
                knownContentTypes.add("text/javascript");
                refreshTable();
            });
            
            popupMenu.add(scanItem);
            popupMenu.add(scanParamsItem);
            popupMenu.add(xssScanItem);
            popupMenu.add(xssScanParamsItem);
            popupMenu.add(new JSeparator());
            popupMenu.add(intruderItem);
            popupMenu.add(new JSeparator());
            popupMenu.add(copyUrlItem);
            popupMenu.add(deleteItem);
            popupMenu.add(new JSeparator());
            popupMenu.add(clearItem);
            
            setComponentPopupMenu(popupMenu);
            
            getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    int row = getSelectedRow();
                    if (row != -1) {
                        int modelRow = convertRowIndexToModel(row);
                        ReflectedRequest req = displayedRequests.get(modelRow);
                        
                        paramsTableModel.setParams(req.params);
                        
                        requestViewer.setRequest(req.requestResponse.request());
                        responseViewer.setResponse(req.requestResponse.response());
                        
                        requestViewer.setSearchExpression("");
                        responseViewer.setSearchExpression("");
                    }
                }
            });
        }
        
        private void startScan(boolean xssOnly, boolean paramsOnly) {
            ReflectedRequest req = getSelectedRequest();
            if (req != null) {
                if (paramsOnly) {
                    targetedForParameterScan.add(req.id);
                }
                
                if (xssOnly) {
                    api.logging().logToOutput("Warning: Granular XSS-only scan is not supported by the current Montoya API. Performing full active scan" + (paramsOnly ? " on parameters." : "."));
                }

                Audit audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
                audit.addRequest(req.requestResponse.request());
            }
        }

        private ReflectedRequest getSelectedRequest() {
            int row = getSelectedRow();
            if (row != -1) {
                int modelRow = convertRowIndexToModel(row);
                return displayedRequests.get(modelRow);
            }
            return null;
        }
    }

    private class ParamsTableModel extends AbstractTableModel {
        private static final String[] COLS = {"Parameter name", "Parameter value", "Reflected value"};
        private List<ReflectedParam> currentParams = new ArrayList<>();

        public void setParams(List<ReflectedParam> params) {
            this.currentParams = params;
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() { return currentParams.size(); }
        @Override
        public int getColumnCount() { return COLS.length; }
        @Override
        public String getColumnName(int col) { return COLS[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            ReflectedParam param = currentParams.get(row);
            switch (col) {
                case 0: return param.name;
                case 1: return param.value;
                case 2: return param.reflectedValue;
                default: return "";
            }
        }
    }

    private class ParamsTable extends JTable {
        public ParamsTable(TableModel model) {
            super(model);
            setAutoCreateRowSorter(true);
            setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            
            getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    int row = getSelectedRow();
                    if (row != -1) {
                        int modelRow = convertRowIndexToModel(row);
                        ParamsTableModel tableModel = (ParamsTableModel) getModel();
                        ReflectedParam param = tableModel.currentParams.get(modelRow);
                        
                        // Native Search Highlighting
                        requestViewer.setSearchExpression(param.reflectedValue);
                        responseViewer.setSearchExpression(param.reflectedValue);
                    }
                }
            });
        }
    }
}