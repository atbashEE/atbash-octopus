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
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.util.StringUtils;

import javax.net.ssl.SSLSocketFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;


/**
 * PKI mutual TLS client authentication at the Token endpoint. The client
 * certificate is PKI bound, as opposed to
 * {@link SelfSignedTLSClientAuthentication self_signed_tls_client_auth} which
 * relies on a self-signed certificate. Implements
 * {@link ClientAuthenticationMethod#TLS_CLIENT_AUTH}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (draft-ietf-oauth-mtls-15), section 2.1.
 * </ul>
 */
public class PKITLSClientAuthentication extends TLSClientAuthentication {


    /**
     * The client X.509 certificate subject DN.
     */
    private final String certSubjectDN;


    /**
     * Creates a new PKI mutual TLS client authentication. This constructor
     * is intended for an outgoing token request.
     *
     * @param clientID         The client identifier. Must not be
     *                         {@code null}.
     * @param sslSocketFactory The SSL socket factory to use for the
     *                         outgoing HTTPS request and to present the
     *                         client certificate(s), {@code null} to use
     *                         the default one.
     */
    public PKITLSClientAuthentication(ClientID clientID,
                                      SSLSocketFactory sslSocketFactory) {

        super(ClientAuthenticationMethod.TLS_CLIENT_AUTH, clientID, sslSocketFactory);
        certSubjectDN = null;
    }


    /**
     * Creates a new PKI mutual TLS client authentication. This constructor
     * is intended for a received token request.
     *
     * @param clientID      The client identifier. Must not be
     *                      {@code null}.
     * @param certSubjectDN The subject DN of the received validated client
     *                      X.509 certificate. Must not be {@code null}.
     * @deprecated This constructor does set the certificate
     */
    @Deprecated
    public PKITLSClientAuthentication(ClientID clientID,
                                      String certSubjectDN) {

        super(ClientAuthenticationMethod.TLS_CLIENT_AUTH, clientID, (X509Certificate) null);

        if (certSubjectDN == null) {
            throw new IllegalArgumentException("The X.509 client certificate subject DN must not be null");
        }
        this.certSubjectDN = certSubjectDN;
    }


    /**
     * Creates a new PKI mutual TLS client authentication. This constructor
     * is intended for a received token request.
     *
     * @param clientID    The client identifier. Must not be {@code null}.
     * @param certificate The validated client X.509 certificate from the
     *                    received HTTPS request. Must not be {@code null}.
     */
    public PKITLSClientAuthentication(ClientID clientID,
                                      X509Certificate certificate) {

        super(ClientAuthenticationMethod.TLS_CLIENT_AUTH, clientID, certificate);

        if (certificate == null) {
            throw new IllegalArgumentException("The X.509 client certificate must not be null");
        }
        this.certSubjectDN = certificate.getSubjectX500Principal().getName();
    }


    /**
     * Gets the subject DN of the received validated client X.509
     * certificate.
     *
     * @return The subject DN.
     */
    public String getClientX509CertificateSubjectDN() {

        return certSubjectDN;
    }


    /**
     * Parses a PKI mutual TLS client authentication from the specified
     * HTTP request.
     *
     * @param httpRequest The HTTP request to parse. Must not be
     *                    {@code null} and must include a validated client
     *                    X.509 certificate.
     * @return The PKI mutual TLS client authentication.
     * @throws OAuth2JSONParseException If the {@code client_id} or client X.509
     *                                  certificate is missing.
     */
    public static PKITLSClientAuthentication parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        String query = httpRequest.getQuery();

        if (query == null) {
            throw new OAuth2JSONParseException("Missing HTTP POST request entity body");
        }

        Map<String, List<String>> params = URLUtils.parseParameters(query);

        String clientIDString = MultivaluedMapUtils.getFirstValue(params, "client_id");

        if (StringUtils.isEmpty(clientIDString)) {
            throw new OAuth2JSONParseException("Missing client_id parameter");
        }

        if (httpRequest.getClientX509Certificate() == null) {
            throw new OAuth2JSONParseException("Missing client X.509 certificate");
        }

        return new PKITLSClientAuthentication(
                new ClientID(clientIDString),
                httpRequest.getClientX509Certificate()
        );
    }
}
