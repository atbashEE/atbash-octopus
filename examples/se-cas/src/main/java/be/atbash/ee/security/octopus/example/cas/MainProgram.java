/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.atbash.ee.security.octopus.example.cas;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.cas.adapter.CasUserToken;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;

import javax.net.ssl.*;
import java.io.Serializable;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;

/**
 *
 */

public class MainProgram {

    public static void main(String[] args) {

        try {
            SSLContext ctx = SSLContext.getInstance("SSL");
            ctx.init(new KeyManager[0], new TrustManager[]{new DefaultTrustManager()}, new SecureRandom());
            SSLContext.setDefault(ctx);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }

        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        // The above was to support https without validating certificates.

        AuthenticationToken token = new UsernamePasswordToken("casuser", "Mellonx");
        SecurityUtils.getSubject().login(token);

        Subject subject = SecurityUtils.getSubject();

        System.out.println("username User principal " + subject.getPrincipal().getUserName());
        Collection<CasUserToken> casUserTokens = subject.getPrincipals().byType(CasUserToken.class);
        if (!casUserTokens.isEmpty()) {
            CasUserToken casUserToken = casUserTokens.iterator().next();

            for (Map.Entry<String, Serializable> entry : casUserToken.getUserInfo().entrySet()) {
                System.out.println(String.format("%s -> %s", entry.getKey(), entry.getValue()));
            }
        }

    }

    public static class DefaultTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }


}