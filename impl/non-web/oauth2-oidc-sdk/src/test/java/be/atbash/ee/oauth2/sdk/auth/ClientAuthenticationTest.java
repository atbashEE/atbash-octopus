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
package be.atbash.ee.oauth2.sdk.auth;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.http.X509CertificateGenerator;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import org.junit.Test;

import java.net.URL;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the base client authentication class.
 */
public class ClientAuthenticationTest {


    // See issue 141
    @Test
    public void testParseClientSecretPostNullSecret()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://googleapis.com/oauth2/v3/token"));
        httpRequest.setContentType("application/x-www-form-urlencoded");
        httpRequest.setQuery("code=4%2FiLoSjco7cxQJSnXBxaxaKCFGG0Au6Rm4H0ZrFV2-5jg&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_id=407408718192.apps.googleusercontent.com&client_secret=&scope=&grant_type=authorization_code");

        ClientAuthentication auth = ClientAuthentication.parse(httpRequest);
        assertThat(auth).isNull();
    }

    @Test
    public void testParseClientSecretJWTNull()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://googleapis.com/oauth2/v3/token"));
        httpRequest.setContentType("application/x-www-form-urlencoded");
        httpRequest.setQuery("code=4%2FiLoSjco7cxQJSnXBxaxaKCFGG0Au6Rm4H0ZrFV2-5jg&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_assertion_type=&client_assertion=&scope=&grant_type=authorization_code");

        ClientAuthentication auth = ClientAuthentication.parse(httpRequest);
        assertThat(auth).isNull();
    }

    @Test
    public void testSelfSignedClientCertificateAuthentication_fromCertOnly()
            throws Exception {

        X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("client_id=123");
        httpRequest.setClientX509Certificate(clientCert);

        SelfSignedTLSClientAuthentication clientAuth = (SelfSignedTLSClientAuthentication) ClientAuthentication.parse(httpRequest);
        assertThat(clientAuth.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(clientAuth.getSSLSocketFactory()).isNull();
        assertThat(clientAuth.getClientX509Certificate()).isEqualTo(clientCert);
    }

    @Test
    public void testSelfSignedClientCertificateAuthentication_withSubjectAndRootParams()
            throws Exception {

        X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("client_id=123");
        httpRequest.setClientX509Certificate(clientCert);
        httpRequest.setClientX509CertificateRootDN(clientCert.getIssuerX500Principal().getName());
        httpRequest.setClientX509CertificateSubjectDN(clientCert.getSubjectX500Principal().getName());

        SelfSignedTLSClientAuthentication clientAuth = (SelfSignedTLSClientAuthentication) ClientAuthentication.parse(httpRequest);
        assertThat(clientAuth.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(clientAuth.getSSLSocketFactory()).isNull();
        assertThat(clientAuth.getClientX509Certificate()).isEqualTo(clientCert);
    }

    @Test
    public void testSelfSignedClientCertificateAuthentication_detectIssuerMismatch()
            throws Exception {

        X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("client_id=123");
        httpRequest.setClientX509Certificate(clientCert);
        httpRequest.setClientX509CertificateRootDN("cn=invalidIssuer");
        httpRequest.setClientX509CertificateSubjectDN(clientCert.getSubjectX500Principal().getName());

        try {
            ClientAuthentication.parse(httpRequest);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Client X.509 certificate issuer DN doesn't match HTTP request metadata");
        }
    }

    @Test
    public void testSelfSignedClientCertificateAuthentication_detectSubjectMismatch()
            throws Exception {

        X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("client_id=123");
        httpRequest.setClientX509Certificate(clientCert);
        httpRequest.setClientX509CertificateRootDN(clientCert.getIssuerX500Principal().getName());
        httpRequest.setClientX509CertificateSubjectDN("cn=invalidSubject");

        try {
            ClientAuthentication.parse(httpRequest);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Client X.509 certificate subject DN doesn't match HTTP request metadata");
        }
    }

    @Test
    public void testTLSClientCertificateAuthentication()
            throws Exception {

        X509Certificate clientCert = X509CertificateGenerator.generateSelfSignedNotSelfIssuedCertificate("issuer", "client-123");

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("client_id=123");
        httpRequest.setClientX509Certificate(clientCert);
        httpRequest.setClientX509CertificateSubjectDN(clientCert.getSubjectDN().getName());

        PKITLSClientAuthentication clientAuth = (PKITLSClientAuthentication) ClientAuthentication.parse(httpRequest);
        assertThat(clientAuth.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(clientAuth.getSSLSocketFactory()).isNull();
        assertThat(clientAuth.getClientX509CertificateSubjectDN()).isEqualTo("CN=client-123");
    }

    @Test
    public void testClientAuthenticationNone()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("client_id=123");

        assertThat(ClientAuthentication.parse(httpRequest)).isNull();
    }


}
