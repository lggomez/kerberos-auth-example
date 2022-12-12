package auth.kerberos.example.okhttp3;

import auth.kerberos.example.commons.security.SpnegoEngine;
import okhttp3.Authenticator;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;
import org.ietf.jgss.GSSException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class KerberosProxyAuthenticator implements Authenticator {
    private final String proxyHost;

    public KerberosProxyAuthenticator(@NotNull String proxyHost) {
        this.proxyHost = proxyHost;
    }

    @Nullable
    @Override
    public Request authenticate(@Nullable Route route, @NotNull Response response) {
        if (response.request().header("Proxy-Authorization") != null) {
            return null; // Give up, we've already failed to authenticate.
        }

        // Generate SPNEGO token via GSSAPI wrapper
        String token = null;
        try {
            token = SpnegoEngine.instance(
                    proxyHost,
                    null, // To be populated by JAAS config
                    "spnego-okhttp-" + this.hashCode()).generateToken();
        } catch (GSSException e) {
            throw new RuntimeException(e);
        }
        String challengeToken = "Negotiate " + token;

        Request returnObj = response.request().newBuilder()
                .header("Proxy-Authorization", challengeToken)
                .build();

        return returnObj;
    }
}
