/*
 * Copyright (c) 2010-2012 Sonatype, Inc. All rights reserved.
 * Modifications copyright (C) 2022 MuleSoft, Inc.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
/*
 * ====================================================================
 *
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */

package auth.kerberos.example.commons.security;

import org.apache.commons.codec.binary.Base64;
import org.ietf.jgss.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.HashMap;
import java.util.Map;

/**
 * GSSAPI wrapper for SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism) token generation.
 */
public class SpnegoEngine {
    static final Oid GSS_KRB5_MECH_OID;
    static final Oid GSS_SPNEGO_MECH_OID;
    /*
     * SPNEGO GSSAPI mechanism OID. See https://oidref.com/1.3.6.1.5.5.2
     * */
    private static final String GSS_SPNEGO_MECH_OIDSTR = "1.3.6.1.5.5.2";
    /*
     * Kerberos V5 GSSAPI mechanism OID. See https://oidref.com/1.2.840.113554.1.2.2
     * */
    private static final String GSS_KRB5_MECH_OIDSTR = "1.2.840.113554.1.2.2";

    private static final Map<String, SpnegoEngine> instances = new HashMap<>();

    static {
        try {
            GSS_KRB5_MECH_OID = new Oid(GSS_KRB5_MECH_OIDSTR);
            GSS_SPNEGO_MECH_OID = new Oid(GSS_SPNEGO_MECH_OIDSTR);
        } catch (GSSException e) {
            throw new RuntimeException(e);
        }
    }

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final String servicePrincipalName;
    private final Map<String, String> customLoginConfig;
    private final Base64 base64codec;

    public SpnegoEngine(final String servicePrincipalName,
                        final Map<String, String> customLoginConfig) {
        this.servicePrincipalName = servicePrincipalName;
        this.customLoginConfig = customLoginConfig;
        this.base64codec = new Base64(0);
    }

    public static SpnegoEngine instance(final String servicePrincipalName,
                                        final Map<String, String> customLoginConfig,
                                        final String loginContextName) {
        String key = "";
        if (customLoginConfig != null && !customLoginConfig.isEmpty()) {
            StringBuilder customLoginConfigKeyValues = new StringBuilder();
            for (String loginConfigKey : customLoginConfig.keySet()) {
                customLoginConfigKeyValues.append(loginConfigKey).append("=")
                        .append(customLoginConfig.get(loginConfigKey));
            }
            key = customLoginConfigKeyValues.toString();
        }
        if (loginContextName != null) {
            key += loginContextName;
        }
        if (!instances.containsKey(key)) {
            instances.put(key, new SpnegoEngine(
                    servicePrincipalName,
                    customLoginConfig
            ));
        }
        return instances.get(key);
    }

    public String generateToken() throws GSSException {
        byte[] token = generateGSSToken(GSS_SPNEGO_MECH_OID, "HTTP", servicePrincipalName);
        return new String(this.base64codec.encode(token));
    }

    protected byte[] generateGSSToken(
            final Oid oid, final String serviceName, final String authServer) throws GSSException {
        byte[] inputBuff = new byte[]{};
        if (inputBuff == null) {
            inputBuff = new byte[0];
        }
        final GSSManager manager = GSSManager.getInstance();

        String proxyServicePrincipal = serviceName + "@" + authServer;
        GSSName gssName = manager.createName(proxyServicePrincipal,
                GSSName.NT_HOSTBASED_SERVICE);

        final GSSContext gssContext = manager.createContext(
                gssName.canonicalize(oid),
                oid,
                null,
                GSSContext.DEFAULT_LIFETIME);
        gssContext.requestMutualAuth(true);
        //gssContext.requestCredDeleg(true);

        return gssContext.initSecContext(inputBuff, 0, inputBuff.length);
    }
}
