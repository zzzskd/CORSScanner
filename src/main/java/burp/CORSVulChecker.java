package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CORSVulChecker {
    // 原始请求
    private IHttpRequestResponse originalIHttpRequestResponse;
    private IRequestInfo originalIRequestInfo;

    // 用于检测是否存在跨域漏洞的请求
    private IHttpRequestResponse checkIHttpRequestResponse;

    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    private PrintWriter std;

    private boolean isVul;
    private String originHeaderName = "Origin";
    private String originHeaderValue;

    public CORSVulChecker(IBurpExtenderCallbacks callbacks, IHttpRequestResponse iHttpRequestResponse, PrintWriter std) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.originalIHttpRequestResponse = iHttpRequestResponse;
        this.originalIRequestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        this.std = std;

        String protocol = this.originalIRequestInfo.getUrl().getProtocol();
        if (protocol.equals("https")) {
            this.originHeaderValue = "https://evil.com";
        } else {
            this.originHeaderValue = "http://evil.com";
        }
    }


    public boolean isSimpleRequestMethod() {
        // 请求方法判断
        List<String> methods = Arrays.asList("GET", "HEAD", "POST");
        String method = originalIRequestInfo.getMethod();
        if (!methods.contains(method.toUpperCase())) {
            return false;
        }
        return true;
    }

    public boolean isSimpleRequestHeaders() {
        // https://fetch.spec.whatwg.org/#cors-safelisted-request-header
        // 只做简单判断, 不允许的 byte 字符不做判断
        List<String> headers = originalIRequestInfo.getHeaders();
        String key, value;
        for (String header: headers) {
            String[] tmp = header.split(":", 1);
            key = tmp[0].trim();
            value = tmp[1].trim();
            int valueLength = value.getBytes().length;
            if (valueLength > 128) {
                return false;
            }
            // TODO: 因为到达 burp 的数据包经过了浏览器的处理，添加了一些 header， 我们需要将将这些头去除掉在判断，那浏览器会自动添加哪些头呢？
        }
        return true;
    }

    public boolean isSimpleRequest() {

       if (!isSimpleRequestMethod()) {
           return false;
       }

        return isSimpleRequestHeaders();
    }

    public boolean preCheck() {
        // 只检查 GET、PUT、POST、DELETE、HEAD 请求
        String method = originalIRequestInfo.getMethod();
        List<String> allowedMethods = Arrays.asList("GET", "PUT", "POST", "DELETE", "HEAD");
        if (!allowedMethods.contains(method.toUpperCase())) {
            return false;
        }
        return true;
    }
    public boolean check() {

        if (!preCheck()) {
            return false;
        }

        // isSimpleRequest();

        // IHttpService 接口用于提供关于 HTTP 服务信息的细节
        IHttpService httpService = this.originalIHttpRequestResponse.getHttpService();

        // 修改/添加 header 中 Origin 中的值
        List<String> oldHeaders = originalIRequestInfo.getHeaders();
        List<String> newHeaders = new ArrayList<String>();
        for (String header: oldHeaders) {
            if (header.toLowerCase().startsWith("origin")) {
                continue;
            }
            newHeaders.add(header);
        }
        newHeaders.add(originHeaderName + ": " + originHeaderValue);

        // 获取 http body 内容: 先获取整个 http 请求, 然后分割掉 http header 便是 http body
        String request = new String(originalIHttpRequestResponse.getRequest());
        int splitPos = originalIRequestInfo.getBodyOffset();
        byte[] httpBody = request.substring(splitPos).getBytes();

        // 拼接成完整的 http request
        byte[] newRequest = helpers.buildHttpMessage(newHeaders, httpBody);


        // 发送请求
        checkIHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);

        // 判断 Access-Control-Allow-Origin 与 Access-Control-Allow-Credentials
        IResponseInfo iResponseInfo = helpers.analyzeResponse(checkIHttpRequestResponse.getResponse());
        List<String> responseHeaders = iResponseInfo.getHeaders();

        boolean acao = false, acac = false;
        for (String header: responseHeaders) {
            if (!header.contains(":")) {
                // HTTP/1.1 200 OK 也是 HTTP header 的一部分, 需要忽略
                continue;
            }

            String[] tmp = header.split(":", 2);
            String key = tmp[0].trim();
            String value = tmp[1].trim();
            std.println(key + value);
            if (key.toLowerCase().startsWith("access-control-allow-origin") && value.contains(originHeaderValue)) {
                // acao -> Access-Control-Allow-Origin
                acao = true;
            }

            if (key.toLowerCase().startsWith("access-control-allow-credentials") && value.contains("true")) {
                // acac -> Access-Control-Allow-Credentials
                acac = true;
            }
        }


        isVul = acao && acac;
        return isVul;
    }

    public boolean isVul() {
        return isVul;
    }

    public IHttpRequestResponse getOriginalIHttpRequestResponse() {
        return originalIHttpRequestResponse;
    }

    public IHttpRequestResponse getCheckIHttpRequestResponse() {
        return checkIHttpRequestResponse;
    }
}
