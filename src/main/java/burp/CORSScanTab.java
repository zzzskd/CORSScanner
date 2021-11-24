package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class CORSScanTab implements ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter std;

    private String name;

    // UI 组件
    private JSplitPane mainPane;
    private VulListTableModel vulListTableModel;
    private JTable vulListTable;
    private JTabbedPane vulDetailTabbedPane;
    private IMessageEditor originalRequestViewer;
    private IMessageEditor checkRequestViewer;
    private IMessageEditor originalResponseViewer;
    private IMessageEditor checkResponseViewer;

    // 漏洞数据
    private List<Vul> vulList;


    public CORSScanTab(IBurpExtenderCallbacks callbacks, PrintWriter std, String name) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.std = std;
        this.name = name;
        this.vulList = new ArrayList<Vul>();

        init();
    }

    public void init() {
        // 初始化页面
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                // 主页面
                mainPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // 漏洞列表
                vulListTableModel = new VulListTableModel();  // 用于刷新
                vulListTable = new VulListTable(vulListTableModel);
                JScrollPane scrollPane = new JScrollPane(vulListTable);
                // 绑定到主页面上
                mainPane.setLeftComponent(scrollPane);


                // 漏洞请求数据详情
                vulDetailTabbedPane = new JTabbedPane();
                originalRequestViewer = callbacks.createMessageEditor(new MessageEditor(), false);
                originalResponseViewer = callbacks.createMessageEditor(new MessageEditor(), false);
                checkRequestViewer = callbacks.createMessageEditor(new MessageEditor(), false);
                checkResponseViewer = callbacks.createMessageEditor(new MessageEditor(), false);
                vulDetailTabbedPane.addTab("Original Request", originalRequestViewer.getComponent());
                vulDetailTabbedPane.addTab("Original Response", originalResponseViewer.getComponent());
                vulDetailTabbedPane.addTab("Check Request", checkRequestViewer.getComponent());
                vulDetailTabbedPane.addTab("Check Response", checkResponseViewer.getComponent());
                // 绑定到主页面
                mainPane.setRightComponent(vulDetailTabbedPane);

                callbacks.customizeUiComponent(mainPane);

                callbacks.addSuiteTab(CORSScanTab.this);
            }
        });

    }

    public String getTabCaption() {
        return name;
    }

    public Component getUiComponent() {
        return mainPane;
    }

    public void addVul(Vul vul) {
        vulList.add(vul);
        // 刷新数据
        vulListTableModel.fireTableDataChanged();
    }

    // 漏洞列表 Table 数据模型
    private class VulListTableModel extends DefaultTableModel {
        private final String[] columnNames = {"#", "Host", "Method", "URL"};

        @Override
        public int getRowCount() {
            return vulList.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Object getValueAt(int row, int column) {
            Vul vul = vulList.get(row);
            String[] vulRow = vul.getVulRow();
            if (column == 0) {
                return row;
            }
            return vulRow[column-1];
        }
    }

    private class VulListTable extends JTable {

        public VulListTable(TableModel dm) {
            super(dm, null, null);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            // 点击时更新下方的漏洞详情
            Vul vul = vulList.get(row);
            originalRequestViewer.setMessage(vul.getOriginRequest(), true);
            originalResponseViewer.setMessage(vul.getOriginResponse(), false);
            checkRequestViewer.setMessage(vul.getCheckRequest(), true);
            checkResponseViewer.setMessage(vul.getCheckResponse(), false);

            super.changeSelection(row, col, toggle, extend);
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            // 不可编辑
            return false;
        }
    }

    private class MessageEditor implements IMessageEditorController {

        public IHttpService getHttpService() {
            return null;
        }

        public byte[] getRequest() {
            return new byte[0];
        }

        public byte[] getResponse() {
            return new byte[0];
        }
    }
}
