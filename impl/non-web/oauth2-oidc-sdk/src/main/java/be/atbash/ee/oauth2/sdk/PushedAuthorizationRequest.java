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
package be.atbash.ee.oauth2.sdk;


import be.atbash.ee.oauth2.sdk.auth.ClientAuthentication;
import be.atbash.ee.oauth2.sdk.auth.ClientSecretBasic;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.openid.connect.sdk.AuthenticationRequest;
import be.atbash.ee.openid.connect.sdk.op.AuthenticationRequestDetector;
import be.atbash.util.StringUtils;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;


/**
 * Pushed authorisation request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /as/par HTTP/1.1
 * Host: as.example.com
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
 *
 * response_type=code
 * &client_id=s6BhdRkqt3&state=af0ifjsldkj
 * &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Pushed Authorization Requests
 *         (draft-lodderstedt-oauth-par-01)
 * </ul>
 */
// FIXME Will this be used in Octopus?
public class PushedAuthorizationRequest extends AbstractOptionallyAuthenticatedRequest {


    /**
     * The pushed authorisation request.
     */
    private final AuthorizationRequest authzRequest;


    /**
     * Creates a new authenticated pushed authorisation request for a
     * confidential client.
     *
     * @param uri          The URI of the token endpoint. May be
     *                     {@code null} if the {@link #toHTTPRequest}
     *                     method will not be used.
     * @param clientAuth   The client authentication. Must not be
     *                     {@code null}.
     * @param authzRequest The authorisation request. Must not be
     *                     {@code null}.
     */
    public PushedAuthorizationRequest(final URI uri,
                                      final ClientAuthentication clientAuth,
                                      final AuthorizationRequest authzRequest) {
        super(uri, clientAuth);

        if (clientAuth == null) {
            throw new IllegalArgumentException("The client authentication must not be null");
        }

        if (authzRequest == null) {
            throw new IllegalArgumentException("The authorization request must not be null");
        }
        if (authzRequest.getRequestURI() != null) {
            throw new IllegalArgumentException("Authorization request_uri parameter not allowed");
        }
        this.authzRequest = authzRequest;
    }


    /**
     * Creates a new pushed authorisation request for a public client.
     *
     * @param uri          The URI of the token endpoint. May be
     *                     {@code null} if the {@link #toHTTPRequest}
     *                     method will not be used.
     * @param authzRequest The authorisation request. Must not be
     *                     {@code null}.
     */
    public PushedAuthorizationRequest(final URI uri,
                                      final AuthorizationRequest authzRequest) {

        super(uri, null);
        if (authzRequest == null) {
            throw new IllegalArgumentException("The authorization request must not be null");
        }
        if (authzRequest.getRequestURI() != null) {
            throw new IllegalArgumentException("Authorization request_uri parameter not allowed");
        }
        this.authzRequest = authzRequest;
    }


    /**
     * Returns the pushed authorisation request.
     *
     * @return The pushed authorisation request.
     */
    public AuthorizationRequest getAuthorizationRequest() {
        return authzRequest;
    }


    @Override
    public HTTPRequest toHTTPRequest() {

        if (getEndpointURI() == null) {
            throw new SerializeException("The endpoint URI is not specified");
        }

        URL url;
        try {
            url = getEndpointURI().toURL();
        } catch (MalformedURLException e) {
            throw new SerializeException(e.getMessage(), e);
        }

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, url);
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

        if (getClientAuthentication() != null) {
            getClientAuthentication().applyTo(httpRequest);
        }

        Map<String, List<String>> params = httpRequest.getQueryParameters();
        params.putAll(authzRequest.toParameters());
        httpRequest.setQuery(URLUtils.serializeParameters(params));

        return httpRequest;
    }


    /**
     * Parses a pushed authorisation request from the specified HTTP
     * request.
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The pushed authorisation request.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to a
     *                                  pushed authorisation request.
     */
    public static PushedAuthorizationRequest parse(final HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        // Only HTTP POST accepted
        URI uri;
        try {
            uri = httpRequest.getURL().toURI();
        } catch (URISyntaxException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }

        httpRequest.ensureMethod(HTTPRequest.Method.POST);
        httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);

        // Parse client authentication, if any
        ClientAuthentication clientAuth;
        try {
            clientAuth = ClientAuthentication.parse(httpRequest);
        } catch (OAuth2JSONParseException e) {
            throw new OAuth2JSONParseException(e.getMessage(), OAuth2Error.INVALID_REQUEST.appendDescription(": " + e.getMessage()));
        }

        // No fragment! May use query component!
        Map<String, List<String>> params = httpRequest.getQueryParameters();

        // Multiple conflicting client auth methods (issue #203)?
        if (clientAuth instanceof ClientSecretBasic) {
            if (StringUtils.hasText(MultivaluedMapUtils.getFirstValue(params, "client_assertion"))
                    || StringUtils.hasText(MultivaluedMapUtils.getFirstValue(params, "client_assertion_type"))) {
                String msg = "Multiple conflicting client authentication methods found: Basic and JWT assertion";
                throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
            }
        }

        // client_id not required in authZ params if auth is present
        if (!params.containsKey("client_id") && clientAuth != null) {
            params.put("client_id", Collections.singletonList(clientAuth.getClientID().getValue()));
        }

        // Parse the authZ request, allow for OpenID
        AuthorizationRequest authzRequest;
        if (AuthenticationRequestDetector.isLikelyOpenID(params)) {
            authzRequest = AuthenticationRequest.parse(params);
        } else {
            authzRequest = AuthorizationRequest.parse(params);
        }

        if (authzRequest.getRequestURI() != null) {
            String msg = "Authorization request_uri parameter not allowed";
            throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
        }

        if (clientAuth != null) {
            return new PushedAuthorizationRequest(uri, clientAuth, authzRequest);
        } else {
            return new PushedAuthorizationRequest(uri, authzRequest);
        }
    }
}
