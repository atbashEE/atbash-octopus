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
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.token.AccessToken;
import be.atbash.ee.oauth2.sdk.token.RefreshToken;
import be.atbash.ee.oauth2.sdk.token.Token;
import be.atbash.ee.oauth2.sdk.token.TypelessAccessToken;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.util.StringUtils;

import javax.json.Json;
import javax.json.JsonObject;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;


/**
 * Token revocation request. Used to revoke an issued access or refresh token.
 *
 * <p>Example token revocation request for a confidential client:
 *
 * <pre>
 * POST /revoke HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 *
 * token=45ghiukldjahdnhzdauz&amp;token_type_hint=refresh_token
 * </pre>
 *
 * <p>Example token revocation request for a public client:
 *
 * <pre>
 * POST /revoke HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * token=45ghiukldjahdnhzdauz&amp;token_type_hint=refresh_token&amp;client_id=123456
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Revocation (RFC 7009), section 2.1.
 * </ul>
 */
public final class TokenRevocationRequest extends AbstractOptionallyIdentifiedRequest {


    /**
     * The token to revoke.
     */
    private final Token token;


    /**
     * Creates a new token revocation request for a confidential client.
     *
     * @param uri        The URI of the token revocation endpoint. May be
     *                   {@code null} if the {@link #toHTTPRequest} method
     *                   will not be used.
     * @param clientAuth The client authentication. Must not be
     *                   {@code null}.
     * @param token      The access or refresh token to revoke. Must not be
     *                   {@code null}.
     */
    public TokenRevocationRequest(URI uri,
                                  ClientAuthentication clientAuth,
                                  Token token) {

        super(uri, clientAuth);

        if (clientAuth == null) {
            throw new IllegalArgumentException("The client authentication must not be null");
        }

        if (token == null) {
            throw new IllegalArgumentException("The token must not be null");
        }

        this.token = token;
    }


    /**
     * Creates a new token revocation request for a public client.
     *
     * @param uri      The URI of the token revocation endpoint. May be
     *                 {@code null} if the {@link #toHTTPRequest} method
     *                 will not be used.
     * @param clientID The client ID. Must not be {@code null}.
     * @param token    The access or refresh token to revoke. Must not be
     *                 {@code null}.
     */
    public TokenRevocationRequest(URI uri,
                                  ClientID clientID,
                                  Token token) {

        super(uri, clientID);

        if (clientID == null) {
            throw new IllegalArgumentException("The client ID must not be null");
        }

        if (token == null) {
            throw new IllegalArgumentException("The token must not be null");
        }

        this.token = token;
    }


    /**
     * Returns the token to revoke. The {@code instanceof} operator can be
     * used to infer the token type. If it's neither
     * {@link AccessToken} nor
     * {@link RefreshToken} the
     * {@code token_type_hint} has not been provided as part of the token
     * revocation request.
     *
     * @return The token.
     */
    public Token getToken() {

        return token;
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

        Map<String, List<String>> params = new HashMap<>();

        if (getClientID() != null) {
            // public client
            params.put("client_id", Collections.singletonList(getClientID().getValue()));
        }

        params.put("token", Collections.singletonList(token.getValue()));

        if (token instanceof AccessToken) {
            params.put("token_type_hint", Collections.singletonList("access_token"));
        } else if (token instanceof RefreshToken) {
            params.put("token_type_hint", Collections.singletonList("refresh_token"));
        }

        httpRequest.setQuery(URLUtils.serializeParameters(params));

        if (getClientAuthentication() != null) {
            // confidential client
            getClientAuthentication().applyTo(httpRequest);
        }

        return httpRequest;
    }


    /**
     * Parses a token revocation request from the specified HTTP request.
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The token revocation request.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to a
     *                                  token revocation request.
     */
    public static TokenRevocationRequest parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        // Only HTTP POST accepted
        httpRequest.ensureMethod(HTTPRequest.Method.POST);
        httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);

        Map<String, List<String>> params = httpRequest.getQueryParameters();

        String tokenValue = MultivaluedMapUtils.getFirstValue(params, "token");

        if (tokenValue == null || tokenValue.isEmpty()) {
            throw new OAuth2JSONParseException("Missing required token parameter");
        }

        // Detect the token type
        Token token = null;

        String tokenTypeHint = MultivaluedMapUtils.getFirstValue(params, "token_type_hint");

        if (tokenTypeHint == null) {

            // Can be both access or refresh token
            token = new Token() {

                @Override
                public String getValue() {

                    return tokenValue;
                }

                @Override
                public Set<String> getParameterNames() {

                    return Collections.emptySet();
                }

                @Override
                public JsonObject toJSONObject() {

                    return Json.createObjectBuilder().build();
                }

                @Override
                public boolean equals(Object other) {

                    return other instanceof Token && other.toString().equals(tokenValue);
                }
            };

        } else if (tokenTypeHint.equals("access_token")) {

            token = new TypelessAccessToken(tokenValue);

        } else if (tokenTypeHint.equals("refresh_token")) {

            token = new RefreshToken(tokenValue);
        }

        URI uri;

        try {
            uri = httpRequest.getURL().toURI();

        } catch (URISyntaxException e) {

            throw new OAuth2JSONParseException(e.getMessage(), e);
        }

        // Parse client auth
        ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);

        if (clientAuth != null) {
            return new TokenRevocationRequest(uri, clientAuth, token);
        }

        // Public client
        String clientIDString = MultivaluedMapUtils.getFirstValue(params, "client_id");

        if (StringUtils.isEmpty(clientIDString)) {
            throw new OAuth2JSONParseException("Invalid token revocation request: No client authentication or client_id parameter found");
        }

        return new TokenRevocationRequest(uri, new ClientID(clientIDString), token);
    }
}
