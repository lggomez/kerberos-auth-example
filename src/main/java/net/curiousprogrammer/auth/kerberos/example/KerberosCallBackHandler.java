package net.curiousprogrammer.auth.kerberos.example;

import javax.security.auth.callback.*;
import java.security.Security;

/**
 * This is a Kerberos-specific LoginContext CallbackHandler used to inject the default LoginContext for the Kerberos auth.
 * Per JavaSE javax auth API spec, this injection/override applies on the following cases (see below, ours falls in the 2nd category):
 * <p>
 * - If the constructor has a CallbackHandler input parameter, the LoginContext uses the caller-specified CallbackHandler object.
 * <p>
 * - If the constructor does not have a CallbackHandler input parameter, or if the caller specifies a null CallbackHandler object
 * (and a null value is permitted), the LoginContext queries the auth.login.defaultCallbackHandler security property for the fully
 * qualified class name of a default handler implementation. If the security property is not set, then the underlying modules will
 * not have a CallbackHandler for use in communicating with users. The caller thus assumes that the configured modules have
 * alternative means for authenticating the user.
 * <p>
 * - When the LoginContext uses the installed Configuration (instead of a caller-specified Configuration, see above), then this
 * LoginContext must wrap any caller-specified or default CallbackHandler implementation in a new CallbackHandler implementation
 * whose handle method implementation invokes the specified CallbackHandler's handle method in a java.security.AccessController.doPrivileged
 * call constrained by the caller's current AccessControlContext.
 */
public class KerberosCallBackHandler implements CallbackHandler {
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        String user = Security.getProperty("java.security.krb5.login.user");
        String password = Security.getProperty("java.security.krb5.login.password");

        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback nc = (NameCallback) callback;
                nc.setName(user);
            } else if (callback instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback) callback;
                pc.setPassword(password.toCharArray());
            } else {
                throw new UnsupportedCallbackException(callback, "Unknown auth Callback");
            }
        }
    }
}
