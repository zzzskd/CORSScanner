package burp;

public class Vul {
    private IExtensionHelpers helpers;

    private IHttpRequestResponse originIHttpRequestResponse;
    private IHttpRequestResponse checkIHttpRequestResponse;

    private IRequestInfo originIRequestInfo;
    private IRequestInfo checkIRequestInfo;

    private IResponseInfo originIResponseInfo;
    private IResponseInfo checkIResponseInfo;

    public Vul(IExtensionHelpers helpers, IHttpRequestResponse originIHttpRequestResponse, IHttpRequestResponse checkIHttpRequestResponse) {
        this.helpers = helpers;

        this.originIHttpRequestResponse = originIHttpRequestResponse;
        this.checkIHttpRequestResponse = checkIHttpRequestResponse;

        this.originIRequestInfo = this.helpers.analyzeRequest(originIHttpRequestResponse);
        this.checkIRequestInfo = this.helpers.analyzeRequest(checkIHttpRequestResponse);

        this.originIResponseInfo = this.helpers.analyzeResponse(originIHttpRequestResponse.getResponse());
        this.checkIResponseInfo = this.helpers.analyzeResponse(checkIHttpRequestResponse.getResponse());
    }

    public String[] getVulRow() {
        String[] row = new String[] {
                originIRequestInfo.getUrl().getHost(),
                originIRequestInfo.getMethod(),
                originIRequestInfo.getUrl().getPath()
        };
        return row;
    }

    public byte[] getOriginRequest() {
        return originIHttpRequestResponse.getRequest();
    }

    public byte[] getOriginResponse() {
        return originIHttpRequestResponse.getResponse();
    }

    public byte[] getCheckRequest() {
        return checkIHttpRequestResponse.getRequest();
    }
    public byte[] getCheckResponse() {
        return checkIHttpRequestResponse.getResponse();
    }
}
