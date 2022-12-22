package auth.kerberos.example.okhttp3;

import auth.kerberos.example.commons.security.KerberosCallBackHandler;
import auth.kerberos.example.okhttp3.transport.http.ExampleAsyncCallback;
import auth.kerberos.example.okhttp3.transport.ws.ProxiedWebSocket;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.jetbrains.annotations.NotNull;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * See "HttpClient set credentials for Kerberos authentication":
 * https://stackoverflow.com/questions/21629132/httpclient-set-credentials-for-kerberos-authentication
 * <p>
 * The idea is to show how to authenticate against Kerberos-enabled proxy server with apache HTTP client.
 * The tricky part is to make sure that provided credentials can be used to obtain Kerberos TGT ticket
 * in case no ticket is already available in ticket OS cache.
 * We want to avoid entering password manually via stdin and instead want to use pre-configured password
 * <p>
 * Notes:
 * - You need to have a valid /etc/krb5.conf in place
 * - Set proper username/password in USER and PASSWORD constants, also PROXY_HOST and PROXY_PORT
 *
 * @see KerberosCallBackHandler
 */
public class Main {
    public static final String HTTP_HOST = "http://ifconfig.me/ip";
    public static final String WS_HOST = "wss://ws.postman-echo.com/raw";

    private static OkHttpClient httpClient;
    private static OkHttpClient wsClient;

    public static void main(String[] args) throws InterruptedException {
        final boolean RUN_HTTP_INSTEADOF_WS = true;
        final int REQUEST_RETRIES = 1000;
        final String USER = "user";
        final String PASSWORD = "pass";
        final String PROXY_HOST = "proxy.com";
        final int PROXY_PORT = 3128;

        System.setProperty("java.security.krb5.conf", "/etc/krb5.conf");
        // Bypass JAAS requirement and directly authenticate via CallbackHandler
        // See https://docs.oracle.com/javase/7/docs/technotes/guides/security/jgss/tutorials/BasicClientServer.html
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");


        // Set login credentials for CallbackHandler using custom security properties.
        // These security properties are non-standard and custom for our application, thus not colliding w/other auth feature flags
        Security.setProperty("java.security.krb5.login.user", USER);
        Security.setProperty("java.security.krb5.login.password", PASSWORD);

        // Setting default callback handler to avoid prompting for password on command line
        // check https://github.com/frohoff/jdk8u-dev-jdk/blob/master/src/share/classes/sun/security/jgss/GSSUtil.java#L241
        Security.setProperty("auth.login.defaultCallbackHandler", "auth.kerberos.example.commons.security.KerberosCallBackHandler");

        //enableDebugSystemProperties();

        setupHTTPClient(PROXY_HOST, PROXY_PORT);
        setupWSClient(PROXY_HOST, PROXY_PORT);

        if (RUN_HTTP_INSTEADOF_WS) {
            System.out.println("********Performing HTTP requests");
            CountDownLatch countDownLatch = new CountDownLatch(REQUEST_RETRIES);
            for (int i = 0; i <= REQUEST_RETRIES; i++) {
                // Perform async call
                newHTTPCall().enqueue(new ExampleAsyncCallback(countDownLatch));
            }
            countDownLatch.await();
        } else {
            System.out.println("********Establishing WebSocket connection");
            CountDownLatch countDownLatch = new CountDownLatch(REQUEST_RETRIES);
            ProxiedWebSocket wsWrapper = new ProxiedWebSocket(wsClient, countDownLatch);
            wsWrapper.run(WS_HOST);
            countDownLatch.await();
            wsWrapper.close();
        }

        System.out.println("********DONE");
    }

    @NotNull
    private static Call newHTTPCall() {
        Request request = new Request.Builder()
                .get()
                .url(HTTP_HOST)
                .build();
        return httpClient.newCall(request);
    }

    @NotNull
    private static void setupHTTPClient(String proxyHost, int proxyPort) {
        httpClient = new OkHttpClient.Builder()
                .proxy(new Proxy(Proxy.Type.HTTP, new
                        InetSocketAddress(proxyHost, proxyPort)))
                .proxyAuthenticator(new KerberosProxyAuthenticator(proxyHost))
                .build();
    }

    @NotNull
    private static void setupWSClient(String proxyHost, int proxyPort) {
        wsClient = new OkHttpClient.Builder()
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .proxy(new Proxy(Proxy.Type.HTTP, new
                        InetSocketAddress(proxyHost, proxyPort)))
                .proxyAuthenticator(new KerberosProxyAuthenticator(proxyHost))
                .build();
    }

    private static void enableDebugSystemProperties() {
        // Enable internal GSS/Kerberos debug logs
        System.setProperty("sun.security.jgss.debug", "true");
        //System.setProperty("sun.security.krb5.debug", "true"); // This will enable verbose KDC request logs
        System.setProperty("sun.security.spnego.debug", "true");
        Security.setProperty("java.security.debug", "gssloginconfig,configfile,configparser,logincontext");
    }
}