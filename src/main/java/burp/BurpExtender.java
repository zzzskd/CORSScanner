package burp;

import java.io.PrintWriter;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck {
    public static String NAME = "CORS Scan";

    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter std;

    // UI 显示界面
    public CORSScanTab tab;


    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
        helpers = callbacks.getHelpers();
        std = new PrintWriter(callbacks.getStdout(), true);

        std.println("Author: n0th1n9");

        callbacks.setExtensionName("CORS CrossDomain Vul Scan");
        callbacks.registerScannerCheck(this);

        tab = new CORSScanTab(callbacks, std, NAME);
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {

        std.println("[*] Passive Scan: " + helpers.analyzeRequest(iHttpRequestResponse).getUrl().getPath());

        IRequestInfo iRequestInfo = helpers.analyzeRequest(iHttpRequestResponse);
//        CORSVulChecker checker = new CORSVulChecker(iHttpRequestResponse);
        CORSVulChecker checker = new CORSVulChecker(callbacks, iHttpRequestResponse, std);
        boolean isVul = checker.check();


         if (isVul) {
            Vul vul = new Vul(helpers, checker.getOriginalIHttpRequestResponse(), checker.getCheckIHttpRequestResponse());
            tab.addVul(vul);
         }
        return null;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }
}
