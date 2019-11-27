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


import be.atbash.ee.oauth2.sdk.SerializeException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.util.URLUtils;

import javax.mail.internet.ContentType;
import javax.net.ssl.SSLSocketFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map;


/**
 * The base abstract class for mutual TLS client authentication at the Token
 * endpoint.
 */
public abstract class TLSClientAuthentication extends ClientAuthentication {


    /**
     * The validated client X.509 certificate from the received HTTPS
     * request, {@code null} for an outgoing HTTPS request.
     */
    protected final X509Certificate certificate;


    /**
     * The SSL socket factory for an outgoing HTTPS request, {@code null}
     * to use the default one.
     */
    private final SSLSocketFactory sslSocketFactory;


    /**
     * Creates a new abstract mutual TLS client authentication. This
     * constructor is intended for an outgoing token request.
     *
     * @param method           The client authentication method. Must not
     *                         be {@code null}.
     * @param clientID         The client identifier. Must not be
     *                         {@code null}.
     * @param sslSocketFactory The SSL socket factory to use for the
     *                         outgoing HTTPS request and to present the
     *                         client certificate(s), {@code null} to use
     *                         the default one.
     */
    protected TLSClientAuthentication(ClientAuthenticationMethod method,
                                      ClientID clientID,
                                      SSLSocketFactory sslSocketFactory) {

        super(method, clientID);
        this.sslSocketFactory = sslSocketFactory;
        certificate = null;
    }


    /**
     * Creates a new abstract mutual TLS client authentication. This
     * constructor is intended for a received token request.
     *
     * @param method      The client authentication method. Must not be
     *                    {@code null}.
     * @param clientID    The client identifier. Must not be {@code null}.
     * @param certificate The validated client X.509 certificate from the
     *                    received HTTPS request. Should not be
     *                    {@code null}.
     */
    protected TLSClientAuthentication(ClientAuthenticationMethod method,
                                      ClientID clientID,
                                      X509Certificate certificate) {
        super(method, clientID);
        sslSocketFactory = null;
        this.certificate = certificate;
    }


    /**
     * Returns the SSL socket factory to use for an outgoing HTTPS request
     * and to present the client certificate(s).
     *
     * @return The SSL socket factory, {@code null} to use the default one.
     */
    public SSLSocketFactory getSSLSocketFactory() {

        return sslSocketFactory;
    }


    /**
     * The validated client X.509 certificate from the received HTTPS
     * request.
     *
     * @return The validated client X.509 certificate from the received
     * HTTPS request, {@code null} for an outgoing HTTPS request.
     */
    public X509Certificate getClientX509Certificate() {

        return certificate;
    }


    @Override
    public void applyTo(HTTPRequest httpRequest) {

        if (httpRequest.getMethod() != HTTPRequest.Method.POST) {
            throw new SerializeException("The HTTP request method must be POST");
        }

        ContentType ct = httpRequest.getContentType();

        if (ct == null) {
            throw new SerializeException("Missing HTTP Content-Type header");
        }

        if (ct.match(CommonContentTypes.APPLICATION_JSON)) {

            // Possibly request object POST request, nothing to set

        } else if (ct.match(CommonContentTypes.APPLICATION_URLENCODED)) {

            // Token or similar request
            Map<String, List<String>> params = httpRequest.getQueryParameters();
            params.put("client_id", Collections.singletonList(getClientID().getValue()));
            String queryString = URLUtils.serializeParameters(params);
            httpRequest.setQuery(queryString);

        } else {
            throw new SerializeException("The HTTP Content-Type header must be " + CommonContentTypes.APPLICATION_URLENCODED);
        }

        // If set for an outgoing request
        httpRequest.setSSLSocketFactory(sslSocketFactory);
    }
}
