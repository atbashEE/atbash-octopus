/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.oauth2.sdk.token;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.util.StringUtils;

import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import java.util.List;
import java.util.Map;


/**
 * Bearer access token.
 *
 * <p>Example bearer access token serialised to JSON:
 *
 * <pre>
 * {
 *   "access_token" : "2YotnFZFEjr1zCsicMWpAA",
 *   "token_type"   : "bearer",
 *   "expires_in"   : 3600,
 *   "scope"        : "read write"
 * }
 * </pre>
 *
 * <p>The above example token serialised to a HTTP Authorization header:
 *
 * <pre>
 * Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 1.4 and 5.1.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750).
 * </ul>
 */
public class BearerAccessToken extends AccessToken {


    /**
     * Creates a new minimal bearer access token with a randomly generated
     * 256-bit (32-byte) value, Base64URL-encoded. The optional lifetime
     * and scope are left undefined.
     */
    public BearerAccessToken() {

        this(32);
    }


    /**
     * Creates a new minimal bearer access token with a randomly generated
     * value of the specified byte length, Base64URL-encoded. The optional
     * lifetime and scope are left undefined.
     *
     * @param byteLength The byte length of the value to generate. Must be
     *                   greater than one.
     */
    public BearerAccessToken(int byteLength) {

        this(byteLength, 0L, null);
    }


    /**
     * Creates a new bearer access token with a randomly generated 256-bit
     * (32-byte) value, Base64URL-encoded.
     *
     * @param lifetime The lifetime in seconds, 0 if not specified.
     * @param scope    The scope, {@code null} if not specified.
     */
    public BearerAccessToken(long lifetime, Scope scope) {

        this(32, lifetime, scope);
    }


    /**
     * Creates a new bearer access token with a randomly generated value of
     * the specified byte length, Base64URL-encoded.
     *
     * @param byteLength The byte length of the value to generate. Must be
     *                   greater than one.
     * @param lifetime   The lifetime in seconds, 0 if not specified.
     * @param scope      The scope, {@code null} if not specified.
     */
    public BearerAccessToken(int byteLength, long lifetime, Scope scope) {

        super(AccessTokenType.BEARER, byteLength, lifetime, scope);
    }


    /**
     * Creates a new minimal bearer access token with the specified value.
     * The optional lifetime and scope are left undefined.
     *
     * @param value The access token value. Must not be {@code null} or
     *              empty string.
     */
    public BearerAccessToken(String value) {

        this(value, 0L, null);
    }


    /**
     * Creates a new bearer access token with the specified value and
     * optional lifetime and scope.
     *
     * @param value    The access token value. Must not be {@code null} or
     *                 empty string.
     * @param lifetime The lifetime in seconds, 0 if not specified.
     * @param scope    The scope, {@code null} if not specified.
     */
    public BearerAccessToken(String value, long lifetime, Scope scope) {

        super(AccessTokenType.BEARER, value, lifetime, scope);
    }


    /**
     * Returns the HTTP Authorization header value for this bearer access
     * token.
     *
     * <p>Example:
     *
     * <pre>
     * Authorization: Bearer eyJhbGciOiJIUzI1NiJ9
     * </pre>
     *
     * @return The HTTP Authorization header.
     */
    @Override
    public String toAuthorizationHeader() {

        return "Bearer " + getValue();
    }


    @Override
    public boolean equals(Object object) {

        return object instanceof BearerAccessToken &&
                this.toString().equals(object.toString());
    }


    /**
     * Parses a bearer access token from a JSON object access token
     * response.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The bearer access token.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to a
     *                                  bearer access token.
     */
    public static BearerAccessToken parse(JsonObject jsonObject)
            throws OAuth2JSONParseException {

        // Parse and verify type
        AccessTokenType tokenType = new AccessTokenType(jsonObject.getString("token_type"));

        if (!tokenType.equals(AccessTokenType.BEARER)) {
            throw new OAuth2JSONParseException("Token type must be Bearer");
        }


        // Parse value
        String accessTokenValue = jsonObject.getString("access_token");


        // Parse lifetime
        long lifetime = 0;

        if (jsonObject.containsKey("expires_in")) {

            // Lifetime can be a JSON number or string

            if (jsonObject.get("expires_in").getValueType() == JsonValue.ValueType.NUMBER) {

                lifetime = jsonObject.getJsonNumber("expires_in").longValue();
            } else {
                String lifetimeStr = jsonObject.getString("expires_in");

                try {
                    lifetime = new Long(lifetimeStr);

                } catch (NumberFormatException e) {

                    throw new OAuth2JSONParseException("Invalid expires_in parameter, must be integer");
                }
            }
        }


        // Parse scope
        Scope scope = null;

        if (jsonObject.containsKey("scope")) {
            scope = Scope.parse(jsonObject.getString("scope"));
        }


        return new BearerAccessToken(accessTokenValue, lifetime, scope);
    }


    /**
     * Parses an HTTP Authorization header for a bearer access token.
     *
     * @param header The HTTP Authorization header value to parse. May be
     *               {@code null} if the header is missing, in which case
     *               an exception will be thrown.
     * @return The bearer access token.
     * @throws OAuth2JSONParseException If the HTTP Authorization header value
     *                                  couldn't be parsed to a bearer access token.
     */
    public static BearerAccessToken parse(String header)
            throws OAuth2JSONParseException {

        if (StringUtils.isEmpty(header)) {
            throw new OAuth2JSONParseException("Missing HTTP Authorization header", BearerTokenError.MISSING_TOKEN);
        }

        String[] parts = header.split("\\s", 2);

        if (parts.length != 2) {
            throw new OAuth2JSONParseException("Invalid HTTP Authorization header value", BearerTokenError.INVALID_REQUEST);
        }

        if (!parts[0].equals("Bearer")) {
            throw new OAuth2JSONParseException("Token type must be Bearer", BearerTokenError.INVALID_REQUEST);
        }

        try {
            return new BearerAccessToken(parts[1]);

        } catch (IllegalArgumentException e) {

            throw new OAuth2JSONParseException(e.getMessage(), BearerTokenError.INVALID_REQUEST);
        }
    }


    /**
     * Parses a query or form parameters map for a bearer access token.
     *
     * @param parameters The query parameters. Must not be {@code null}.
     * @return The bearer access token.
     * @throws OAuth2JSONParseException If a bearer access token wasn't found in the
     *                                  parameters.
     */
    public static BearerAccessToken parse(Map<String, List<String>> parameters)
            throws OAuth2JSONParseException {

        if (!parameters.containsKey("access_token")) {
            throw new OAuth2JSONParseException("Missing access token parameter", BearerTokenError.MISSING_TOKEN);
        }

        String accessTokenValue = MultivaluedMapUtils.getFirstValue(parameters, "access_token");

        if (StringUtils.isEmpty(accessTokenValue)) {
            throw new OAuth2JSONParseException("Blank / empty access token", BearerTokenError.INVALID_REQUEST);
        }

        return new BearerAccessToken(accessTokenValue);
    }


    /**
     * Parses an HTTP request for a bearer access token.
     *
     * @param request The HTTP request to parse. Must not be {@code null}.
     * @return The bearer access token.
     * @throws OAuth2JSONParseException If a bearer access token wasn't found in the
     *                                  HTTP request.
     */
    public static BearerAccessToken parse(HTTPRequest request)
            throws OAuth2JSONParseException {

        // See http://tools.ietf.org/html/rfc6750#section-2

        String authzHeader = request.getAuthorization();

        if (authzHeader != null) {

            return parse(authzHeader);
        }

        // Try alternative token locations, form and query string are
        // parameters are not differentiated here

        Map<String, List<String>> params = request.getQueryParameters();

        return parse(params);
    }
}
