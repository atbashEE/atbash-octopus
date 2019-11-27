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
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.util.StringUtils;

import javax.security.auth.x500.X500Principal;
import java.util.List;
import java.util.Map;


/**
 * Base abstract class for client authentication at the Token endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 2.3.
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523), section 2.2.
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (draft-ietf-oauth-mtls-15), section 2.
 * </ul>
 */
public abstract class ClientAuthentication {


    /**
     * The client authentication method.
     */
    private final ClientAuthenticationMethod method;


    /**
     * The client ID.
     */
    private final ClientID clientID;


    /**
     * Creates a new abstract client authentication.
     *
     * @param method   The client authentication method. Must not be
     *                 {@code null}.
     * @param clientID The client identifier. Must not be {@code null}.
     */
    protected ClientAuthentication(ClientAuthenticationMethod method, ClientID clientID) {

        if (method == null) {
            throw new IllegalArgumentException("The client authentication method must not be null");
        }

        this.method = method;


        if (clientID == null) {
            throw new IllegalArgumentException("The client identifier must not be null");
        }

        this.clientID = clientID;
    }


    /**
     * Gets the client authentication method.
     *
     * @return The client authentication method.
     */
    public ClientAuthenticationMethod getMethod() {

        return method;
    }


    /**
     * Gets the client identifier.
     *
     * @return The client identifier.
     */
    public ClientID getClientID() {

        return clientID;
    }


    /**
     * Parses the specified HTTP request for a supported client
     * authentication (see {@link ClientAuthenticationMethod}). This method
     * is intended to aid parsing of authenticated
     * {@link be.atbash.ee.oauth2.sdk.TokenRequest}s.
     *
     * @param httpRequest The HTTP request to parse. Must not be
     *                    {@code null}.
     * @return The client authentication method, {@code null} if none or
     * the method is not supported.
     * @throws OAuth2JSONParseException If the inferred client authentication
     *                                  couldn't be parsed.
     */
    public static ClientAuthentication parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        // Check for client secret basic
        if (httpRequest.getAuthorization() != null &&
                httpRequest.getAuthorization().startsWith("Basic")) {

            return ClientSecretBasic.parse(httpRequest);
        }

        // The other methods require HTTP POST with URL-encoded params
        if (httpRequest.getMethod() != HTTPRequest.Method.POST &&
                !httpRequest.getContentType().match(CommonContentTypes.APPLICATION_URLENCODED)) {
            return null; // no auth
        }

        Map<String, List<String>> params = httpRequest.getQueryParameters();

        // We have client secret post
        if (StringUtils.hasText(MultivaluedMapUtils.getFirstValue(params, "client_id")) && StringUtils.hasText(MultivaluedMapUtils.getFirstValue(params, "client_secret"))) {
            return ClientSecretPost.parse(httpRequest);
        }

        // Do we have a signed JWT assertion?
        if (StringUtils.hasText(MultivaluedMapUtils.getFirstValue(params, "client_assertion")) && StringUtils.hasText(MultivaluedMapUtils.getFirstValue(params, "client_assertion_type"))) {
            return JWTAuthentication.parse(httpRequest);
        }

        // Client TLS?
        if (httpRequest.getClientX509Certificate() != null && StringUtils.hasText(MultivaluedMapUtils.getFirstValue(params, "client_id"))) {

            // Check for self-issued first (not for self-signed (too expensive in terms of CPU time)

            X500Principal issuer = httpRequest.getClientX509Certificate().getIssuerX500Principal();
            X500Principal subject = httpRequest.getClientX509Certificate().getSubjectX500Principal();

            if (issuer != null && issuer.equals(subject)) {
                // Additional checks
                if (httpRequest.getClientX509CertificateRootDN() != null) {
                    // If TLS proxy set issuer header it must match the certificate's
                    if (!httpRequest.getClientX509CertificateRootDN().equalsIgnoreCase(issuer.toString())) {
                        throw new OAuth2JSONParseException("Client X.509 certificate issuer DN doesn't match HTTP request metadata");
                    }
                }
                if (httpRequest.getClientX509CertificateSubjectDN() != null) {
                    // If TLS proxy set subject header it must match the certificate's
                    if (!httpRequest.getClientX509CertificateSubjectDN().equalsIgnoreCase(subject.toString())) {
                        throw new OAuth2JSONParseException("Client X.509 certificate subject DN doesn't match HTTP request metadata");
                    }
                }

                // Self-issued (assumes self-signed)
                return SelfSignedTLSClientAuthentication.parse(httpRequest);
            } else {
                // PKI bound
                return PKITLSClientAuthentication.parse(httpRequest);
            }
        }

        return null; // no auth
    }


    /**
     * Applies the authentication to the specified HTTP request by setting
     * its Authorization header and/or POST entity-body parameters
     * (according to the implemented client authentication method).
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     */
    public abstract void applyTo(HTTPRequest httpRequest);
}
