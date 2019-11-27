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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.AbstractRequest;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.SerializeException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URIUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import be.atbash.ee.security.octopus.nimbus.jwt.PlainJWT;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * Back-channel logout request initiated by an OpenID provider (OP).
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /backchannel_logout HTTP/1.1
 * Host: rp.example.org
 * Content-Type: application/x-www-form-urlencoded
 *
 * logout_token=eyJhbGci ... .eyJpc3Mi ... .T3BlbklE ...
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Back-Channel Logout 1.0, section 2.5 (draft 04).
 * </ul>
 */
// FIXME Will this be used in Octopus?
public class BackChannelLogoutRequest extends AbstractRequest {


    /**
     * The logout token.
     */
    private final JWT logoutToken;


    /**
     * Creates a new back-channel logout request.
     *
     * @param uri         The back-channel logout URI. May be {@code null}
     *                    if the {@link #toHTTPRequest} method will not be
     *                    used.
     * @param logoutToken The logout token. Must be signed, or signed and
     *                    encrypted. Must not be {@code null}.
     */
    public BackChannelLogoutRequest(URI uri,
                                    JWT logoutToken) {

        super(uri);

        if (logoutToken == null) {
            throw new IllegalArgumentException("The logout token must not be null");
        }

        if (logoutToken instanceof PlainJWT) {
            throw new IllegalArgumentException("The logout token must not be unsecured (plain)");
        }

        this.logoutToken = logoutToken;
    }


    /**
     * Returns the logout token.
     *
     * @return The logout token.
     */
    public JWT getLogoutToken() {

        return logoutToken;
    }


    /**
     * Returns the parameters for this back-channel logout request.
     *
     * <p>Example parameters:
     *
     * <pre>
     * logout_token=eyJhbGci ... .eyJpc3Mi ... .T3BlbklE ...
     * </pre>
     *
     * @return The parameters.
     */
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = new LinkedHashMap<>();

        try {
            params.put("logout_token", Collections.singletonList(logoutToken.serialize()));
        } catch (IllegalStateException e) {
            throw new SerializeException("Couldn't serialize logout token: " + e.getMessage(), e);
        }

        return params;
    }


    @Override
    public HTTPRequest toHTTPRequest() {

        if (getEndpointURI() == null) {
            throw new SerializeException("The endpoint URI is not specified");
        }

        HTTPRequest httpRequest;

        URL endpointURL;

        try {
            endpointURL = getEndpointURI().toURL();

        } catch (MalformedURLException e) {

            throw new SerializeException(e.getMessage(), e);
        }

        httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpointURL);
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery(URLUtils.serializeParameters(toParameters()));

        return httpRequest;
    }


    /**
     * Parses a back-channel logout request from the specified request body
     * parameters.
     *
     * <p>Example parameters:
     *
     * <pre>
     * logout_token = eyJhbGci ... .eyJpc3Mi ... .T3BlbklE ...
     * </pre>
     *
     * @param params The parameters. Must not be {@code null}.
     * @return The back-channel logout request.
     * @throws OAuth2JSONParseException If the parameters couldn't be parsed to a
     *                                  back-channel logout request.
     */
    public static BackChannelLogoutRequest parse(Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        return parse(null, params);
    }


    /**
     * Parses a back-channel logout request from the specified URI and
     * request body parameters.
     *
     * <p>Example parameters:
     *
     * <pre>
     * logout_token = eyJhbGci ... .eyJpc3Mi ... .T3BlbklE ...
     * </pre>
     *
     * @param uri    The back-channel logout URI. May be {@code null} if
     *               the {@link #toHTTPRequest()} method will not be used.
     * @param params The parameters. Must not be {@code null}.
     * @return The back-channel logout request.
     * @throws OAuth2JSONParseException If the parameters couldn't be parsed to a
     *                                  back-channel logout request.
     */
    public static BackChannelLogoutRequest parse(URI uri, Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        String logoutTokenString = MultivaluedMapUtils.getFirstValue(params, "logout_token");

        if (logoutTokenString == null) {
            throw new OAuth2JSONParseException("Missing logout_token parameter");
        }

        JWT logoutToken;

        try {
            logoutToken = JWTParser.parse(logoutTokenString);
        } catch (java.text.ParseException e) {
            throw new OAuth2JSONParseException("Invalid logout token: " + e.getMessage(), e);
        }

        try {
            return new BackChannelLogoutRequest(uri, logoutToken);
        } catch (IllegalArgumentException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
    }


    /**
     * Parses a back-channel logout request from the specified HTTP request.
     *
     * <p>Example HTTP request (POST):
     *
     * <pre>
     * POST /backchannel_logout HTTP/1.1
     * Host: rp.example.org
     * Content-Type: application/x-www-form-urlencoded
     *
     * logout_token=eyJhbGci ... .eyJpc3Mi ... .T3BlbklE ...
     * </pre>
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The back-channel logout request.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to a
     *                                  back-channel logout request.
     */
    public static BackChannelLogoutRequest parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        if (!HTTPRequest.Method.POST.equals(httpRequest.getMethod())) {
            throw new OAuth2JSONParseException("HTTP POST required");
        }

        // Lenient on content-type

        String query = httpRequest.getQuery();

        if (query == null) {
            throw new OAuth2JSONParseException("Missing URI query string");
        }

        Map<String, List<String>> params = URLUtils.parseParameters(query);

        try {
            return parse(URIUtils.getBaseURI(httpRequest.getURL().toURI()), params);

        } catch (URISyntaxException e) {

            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
    }
}
