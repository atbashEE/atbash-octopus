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
import be.atbash.ee.openid.connect.sdk.token.OIDCTokens;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import java.util.Set;


/**
 * Access and optional refresh token.
 */
public class Tokens {


    /**
     * Access token.
     */
    private final AccessToken accessToken;


    /**
     * Refresh token, {@code null} if not specified.
     */
    private final RefreshToken refreshToken;


    /**
     * Creates a new tokens instance.
     *
     * @param accessToken  The access token. Must not be {@code null}.
     * @param refreshToken The refresh token. If none {@code null}.
     */
    public Tokens(AccessToken accessToken, RefreshToken refreshToken) {

        if (accessToken == null) {
            throw new IllegalArgumentException("The access token must not be null");
        }

        this.accessToken = accessToken;

        this.refreshToken = refreshToken;
    }


    /**
     * Returns the access token.
     *
     * @return The access token.
     */
    public AccessToken getAccessToken() {

        return accessToken;
    }


    /**
     * Returns the access token as type bearer.
     *
     * @return The bearer access token, {@code null} if the type is
     * different.
     */
    public BearerAccessToken getBearerAccessToken() {

        if (accessToken instanceof BearerAccessToken) {
            return (BearerAccessToken) accessToken;
        }

        return null;
    }


    /**
     * Returns the optional refresh token.
     *
     * @return The refresh token, {@code null} if none.
     */
    public RefreshToken getRefreshToken() {

        return refreshToken;
    }


    /**
     * Returns the token parameter names for the included tokens.
     *
     * @return The token parameter names.
     */
    public Set<String> getParameterNames() {

        // Get the std param names for the access + refresh token
        Set<String> paramNames = accessToken.getParameterNames();

        if (refreshToken != null) {
            paramNames.addAll(refreshToken.getParameterNames());
        }

        return paramNames;
    }


    /**
     * Returns the JSON object representation of this token pair.
     *
     * <p>Example JSON object:
     *
     * <pre>
     * {
     *   "access_token"  : "dZdt8BlltORMTz5U",
     *   "refresh_token" : "E87zjAoeNXaSoF1U"
     * }
     * </pre>
     *
     * @return The JSON object representation.
     */
    public JsonObjectBuilder toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder(accessToken.toJSONObject());

        if (refreshToken != null) {
            result.addAll(Json.createObjectBuilder(refreshToken.toJSONObject()));
        }
        return result;
    }


    /**
     * Casts to OpenID Connect tokens.
     *
     * @return The OpenID Connect tokens (including an ID token).
     */
    public OIDCTokens toOIDCTokens() {

        return (OIDCTokens) this;
    }


    @Override
    public String toString() {

        return toJSONObject().build().toString();
    }


    /**
     * Parses an access and optional refresh token from the specified JSON
     * object.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The tokens.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to a
     *                                  tokens instance.
     */
    public static Tokens parse(JsonObject jsonObject)
            throws OAuth2JSONParseException {

        return new Tokens(AccessToken.parse(jsonObject), RefreshToken.parse(jsonObject));
    }
}
