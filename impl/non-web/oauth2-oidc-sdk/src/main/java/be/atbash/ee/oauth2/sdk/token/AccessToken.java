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
package be.atbash.ee.oauth2.sdk.token;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.Scope;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.util.HashSet;
import java.util.Set;


/**
 * The base abstract class for access tokens. Concrete extending classes should
 * be immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 1.4 and 5.1.
 * </ul>
 */
public abstract class AccessToken extends Token {


    /**
     * The access token type.
     */
    private final AccessTokenType type;


    /**
     * Optional lifetime, in seconds.
     */
    private final long lifetime;


    /**
     * Optional scope.
     */
    private final Scope scope;


    /**
     * Creates a new minimal access token with a randomly generated 256-bit
     * (32-byte) value, Base64URL-encoded. The optional lifetime and scope
     * are left undefined.
     *
     * @param type The access token type. Must not be {@code null}.
     */
    public AccessToken(final AccessTokenType type) {

        this(type, 32);
    }


    /**
     * Creates a new minimal access token with a randomly generated value
     * of the specified byte length, Base64URL-encoded. The optional
     * lifetime and scope are left undefined.
     *
     * @param type       The access token type. Must not be {@code null}.
     * @param byteLength The byte length of the value to generate. Must be
     *                   greater than one.
     */
    public AccessToken(final AccessTokenType type, final int byteLength) {

        this(type, byteLength, 0L, null);
    }


    /**
     * Creates a new access token with a randomly generated 256-bit
     * (32-byte) value, Base64URL-encoded.
     *
     * @param type     The access token type. Must not be {@code null}.
     * @param lifetime The lifetime in seconds, 0 if not specified.
     * @param scope    The scope, {@code null} if not specified.
     */
    public AccessToken(final AccessTokenType type,
                       final long lifetime,
                       final Scope scope) {

        this(type, 32, lifetime, scope);
    }


    /**
     * Creates a new access token with a randomly generated value
     * of the specified byte length, Base64URL-encoded, and optional
     * lifetime and scope.
     *
     * @param type       The access token type. Must not be {@code null}.
     * @param byteLength The byte length of the value to generate. Must be
     *                   greater than one.
     * @param lifetime   The lifetime in seconds, 0 if not specified.
     * @param scope      The scope, {@code null} if not specified.
     */
    public AccessToken(final AccessTokenType type,
                       final int byteLength,
                       final long lifetime,
                       final Scope scope) {

        super(byteLength);

        if (type == null) {
            throw new IllegalArgumentException("The access token type must not be null");
        }

        this.type = type;

        this.lifetime = lifetime;
        this.scope = scope;
    }


    /**
     * Creates a new minimal access token with the specified value. The
     * optional lifetime and scope are left undefined.
     *
     * @param type  The access token type. Must not be {@code null}.
     * @param value The access token value. Must not be {@code null} or
     *              empty string.
     */
    public AccessToken(final AccessTokenType type, final String value) {

        this(type, value, 0L, null);
    }


    /**
     * Creates a new access token with the specified value and optional
     * lifetime and scope.
     *
     * @param type     The access token type. Must not be {@code null}.
     * @param value    The access token value. Must not be {@code null} or
     *                 empty string.
     * @param lifetime The lifetime in seconds, 0 if not specified.
     * @param scope    The scope, {@code null} if not specified.
     */
    public AccessToken(final AccessTokenType type,
                       final String value,
                       final long lifetime,
                       final Scope scope) {

        super(value);

        if (type == null) {
            throw new IllegalArgumentException("The access token type must not be null");
        }

        this.type = type;

        this.lifetime = lifetime;
        this.scope = scope;
    }


    /**
     * Returns the access token type.
     *
     * @return The access token type.
     */
    public AccessTokenType getType() {

        return type;
    }


    /**
     * Returns the lifetime of this access token.
     *
     * @return The lifetime in seconds, 0 if not specified.
     */
    public long getLifetime() {

        return lifetime;
    }


    /**
     * Returns the scope of this access token.
     *
     * @return The scope, {@code null} if not specified.
     */
    public Scope getScope() {

        return scope;
    }


    @Override
    public Set<String> getParameterNames() {

        Set<String> paramNames = new HashSet<>();
        paramNames.add("access_token");
        paramNames.add("token_type");

        if (getLifetime() > 0) {
            paramNames.add("expires_in");
        }

        if (getScope() != null) {
            paramNames.add("scope");
        }

        return paramNames;
    }


    @Override
    public JsonObject toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder();


        result.add("access_token", getValue());
        result.add("token_type", type.toString());

        if (getLifetime() > 0) {
            result.add("expires_in", lifetime);
        }

        if (getScope() != null) {
            result.add("scope", scope.toString());
        }

        return result.build();
    }


    @Override
    public String toJSONString() {

        return toJSONObject().toString();
    }


    /**
     * Returns the {@code Authorization} HTTP request header value for this
     * access token.
     *
     * @return The {@code Authorization} header value.
     */
    public abstract String toAuthorizationHeader();


    /**
     * Parses an access token from a JSON object access token response.
     * Only bearer access tokens are supported.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The access token.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to an
     *                                  access token.
     */
    public static AccessToken parse(final JsonObject jsonObject)
            throws OAuth2JSONParseException {

        return BearerAccessToken.parse(jsonObject);
    }


    /**
     * Parses an {@code Authorization} HTTP request header value for an
     * access token. Only bearer access token are supported.
     *
     * @param header The {@code Authorization} header value to parse. Must
     *               not be {@code null}.
     * @return The access token.
     * @throws OAuth2JSONParseException If the {@code Authorization} header value
     *                                  couldn't be parsed to an access token.
     */
    public static AccessToken parse(final String header)
            throws OAuth2JSONParseException {

        return BearerAccessToken.parse(header);
    }
}
