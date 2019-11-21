/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package be.atbash.ee.oauth2.sdk.auth;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.http.X509CertificateGenerator;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import org.junit.Test;

import javax.net.ssl.SSLSocketFactory;
import java.net.URL;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class SelfSignedTLSClientAuthenticationTest {

    @Test
    public void testSSLSocketFactoryConstructor_defaultSSL()
            throws Exception {

        SelfSignedTLSClientAuthentication clientAuth = new SelfSignedTLSClientAuthentication(
                new ClientID("123"),
                (SSLSocketFactory) null);

        assertThat(clientAuth.getMethod()).isEqualTo(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
        assertThat(clientAuth.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(clientAuth.getSSLSocketFactory()).isNull();
        assertThat(clientAuth.getClientX509Certificate()).isNull();

        HTTPRequest httpRequest = new HTTPRequest(
                HTTPRequest.Method.POST,
                new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

        assertThat(httpRequest.getSSLSocketFactory()).isNull();

        clientAuth.applyTo(httpRequest);

        assertThat(httpRequest.getSSLSocketFactory()).isNull();
    }

    @Test
    public void testSSLSocketFactoryConstructor()
            throws Exception {

        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        SelfSignedTLSClientAuthentication clientAuth = new SelfSignedTLSClientAuthentication(
                new ClientID("123"),
                sslSocketFactory
        );

        assertThat(clientAuth.getMethod()).isEqualTo(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
        assertThat(clientAuth.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(clientAuth.getSSLSocketFactory()).isEqualTo(sslSocketFactory);
        assertThat(clientAuth.getClientX509Certificate()).isNull();

        HTTPRequest httpRequest = new HTTPRequest(
                HTTPRequest.Method.POST,
                new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

        assertThat(httpRequest.getSSLSocketFactory()).isNull();

        clientAuth.applyTo(httpRequest);

        assertThat(httpRequest.getSSLSocketFactory()).isEqualTo(sslSocketFactory);
    }

    @Test
    public void testCertificateConstructor()
            throws Exception {

        X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();

        SelfSignedTLSClientAuthentication clientAuth = new SelfSignedTLSClientAuthentication(
                new ClientID("123"),
                clientCert);

        assertThat(clientAuth.getMethod()).isEqualTo(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
        assertThat(clientAuth.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(clientAuth.getSSLSocketFactory()).isNull();
        assertThat(clientAuth.getClientX509Certificate()).isEqualTo(clientCert);

        // This constructor is not intended to be used for setting an
        // HTTPRequest, but still this shouldn't produce any errors
        HTTPRequest httpRequest = new HTTPRequest(
                HTTPRequest.Method.POST,
                new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

        assertThat(httpRequest.getSSLSocketFactory()).isNull();

        clientAuth.applyTo(httpRequest);

        assertThat(httpRequest.getSSLSocketFactory()).isNull();
    }

    @Test
    public void testParse_missingPostEntityBody()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));

        try {
            SelfSignedTLSClientAuthentication.parse(httpRequest);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing HTTP POST request entity body");
        }
    }

    @Test
    public void testParse_missingClientID()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("a=b");

        try {
            SelfSignedTLSClientAuthentication.parse(httpRequest);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing client_id parameter");
        }
    }

    @Test
    public void testParse_emptyClientID()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("client_id=");

        try {
            SelfSignedTLSClientAuthentication.parse(httpRequest);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing client_id parameter");
        }
    }

    @Test
    public void testParse_missingClientCertificate()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("client_id=123");

        try {
            SelfSignedTLSClientAuthentication.parse(httpRequest);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing client X.509 certificate");
        }
    }

    @Test
    public void testParse_ok()
            throws Exception {

        X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("client_id=123");
        httpRequest.setClientX509Certificate(clientCert);

        SelfSignedTLSClientAuthentication clientAuth = SelfSignedTLSClientAuthentication.parse(httpRequest);
        assertThat(clientAuth.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(clientAuth.getSSLSocketFactory()).isNull();
        assertThat(clientAuth.getClientX509Certificate()).isEqualTo(clientCert);
    }
}
