import java.net.MalformedURLException;
import java.net.URL;

public class Test {
    public static void main(String[] args) throws MalformedURLException {
        URL url = new URL("http://a.bo.com");
        System.out.println(url.getProtocol());
    }
}
