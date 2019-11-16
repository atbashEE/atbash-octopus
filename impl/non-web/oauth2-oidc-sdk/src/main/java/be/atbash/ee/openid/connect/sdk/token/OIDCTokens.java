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
package be.atbash.ee.openid.connect.sdk.token;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.token.AccessToken;
import be.atbash.ee.oauth2.sdk.token.RefreshToken;
import be.atbash.ee.oauth2.sdk.token.Tokens;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;

import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.util.Set;


/**
 * ID token, access token and optional refresh token.
 */
public final class OIDCTokens extends Tokens {


    /**
     * The ID Token serialised to a JWT, {@code null} if not specified.
     */
    private final JWT idToken;


    /**
     * The ID Token as raw string (for more efficient serialisation),
     * {@code null} if not specified.
     */
    private final String idTokenString;


    /**
     * Creates a new OpenID Connect tokens instance.
     *
     * @param idToken      The ID token. Must not be {@code null}.
     * @param accessToken  The access token. Must not be {@code null}.
     * @param refreshToken The refresh token. If none {@code null}.
     */
    public OIDCTokens(final JWT idToken, final AccessToken accessToken, final RefreshToken refreshToken) {

        super(accessToken, refreshToken);

        if (idToken == null) {
            throw new IllegalArgumentException("The ID token must not be null");
        }

        this.idToken = idToken;
        idTokenString = null;
    }


    /**
     * Creates a new OpenID Connect tokens instance.
     *
     * @param idTokenString The ID token string. Must not be {@code null}.
     * @param accessToken   The access token. Must not be {@code null}.
     * @param refreshToken  The refresh token. If none {@code null}.
     */
    public OIDCTokens(final String idTokenString, final AccessToken accessToken, final RefreshToken refreshToken) {

        super(accessToken, refreshToken);

        if (idTokenString == null) {
            throw new IllegalArgumentException("The ID token string must not be null");
        }

        this.idTokenString = idTokenString;
        idToken = null;
    }


    /**
     * Creates a new OpenID Connect tokens instance without an ID token.
     * Intended for token responses from a refresh token grant where the ID
     * token is optional.
     *
     * @param accessToken  The access token. Must not be {@code null}.
     * @param refreshToken The refresh token. If none {@code null}.
     */
    public OIDCTokens(final AccessToken accessToken, final RefreshToken refreshToken) {

        super(accessToken, refreshToken);
        this.idToken = null;
        this.idTokenString = null;
    }


    /**
     * Gets the ID token.
     *
     * @return The ID token, {@code null} if none or if parsing to a JWT
     * failed.
     */
    public JWT getIDToken() {

        if (idToken != null) {
            return idToken;
        }

        if (idTokenString != null) {

            try {
                return JWTParser.parse(idTokenString);

            } catch (java.text.ParseException e) {

                return null;
            }
        }

        return null;
    }


    /**
     * Gets the ID token string.
     *
     * @return The ID token string, {@code null} if none or if
     * serialisation to a string failed.
     */
    public String getIDTokenString() {

        if (idTokenString != null) {
            return idTokenString;
        }

        if (idToken != null) {

            // Reproduce originally parsed string if any
            if (idToken.getParsedString() != null) {
                return idToken.getParsedString();
            }

            try {
                return idToken.serialize();

            } catch (IllegalStateException e) {

                return null;
            }
        }

        return null;
    }


    @Override
    public Set<String> getParameterNames() {

        Set<String> paramNames = super.getParameterNames();
        if (idToken != null || idTokenString != null) {
            paramNames.add("id_token");
        }
        return paramNames;
    }


    @Override
    public JsonObjectBuilder toJSONObject() {

        JsonObjectBuilder result = super.toJSONObject();
        if (getIDTokenString() != null) {
            result.add("id_token", getIDTokenString());
        }
        return result;
    }


    /**
     * Parses an OpenID Connect tokens instance from the specified JSON
     * object.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The OpenID Connect tokens.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to an
     *                                  OpenID Connect tokens instance.
     */
    public static OIDCTokens parse(final JsonObject jsonObject)
            throws OAuth2JSONParseException {

        AccessToken accessToken = AccessToken.parse(jsonObject);

        RefreshToken refreshToken = RefreshToken.parse(jsonObject);

        if (jsonObject.get("id_token") != null) {

            JWT idToken;
            try {
                idToken = JWTParser.parse(jsonObject.getString("id_token"));
            } catch (java.text.ParseException e) {
                throw new OAuth2JSONParseException("Couldn't parse ID token: " + e.getMessage(), e);
            }

            return new OIDCTokens(idToken, accessToken, refreshToken);

        } else {

            // Likely a token response from a refresh token grant without an ID token
            return new OIDCTokens(accessToken, refreshToken);
        }
    }
}
