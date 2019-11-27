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

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.util.HashSet;
import java.util.Set;


/**
 * Refresh token.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 1.5.
 * </ul>
 */
public final class RefreshToken extends Token {


    /**
     * Creates a new refresh token with a randomly generated 256-bit
     * (32-byte) value, Base64URL-encoded.
     */
    public RefreshToken() {

        this(32);
    }


    /**
     * Creates a new refresh token with a randomly generated value of the
     * specified length, Base64URL-encoded.
     *
     * @param byteLength The byte length of the value to generate. Must be
     *                   greater than one.
     */
    public RefreshToken(int byteLength) {

        super(byteLength);
    }


    /**
     * Creates a new refresh token with the specified value.
     *
     * @param value The refresh token value. Must not be {@code null} or
     *              empty string.
     */
    public RefreshToken(String value) {

        super(value);
    }


    @Override
    public Set<String> getParameterNames() {

        Set<String> paramNames = new HashSet<>();
        paramNames.add("refresh_token");
        return paramNames;
    }


    @Override
    public JsonObject toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder();

        result.add("refresh_token", getValue());

        return result.build();
    }


    /**
     * Parses a refresh token from a JSON object access token response.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The refresh token, {@code null} if not found.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to a
     *                                  refresh token.
     */
    public static RefreshToken parse(JsonObject jsonObject)
            throws OAuth2JSONParseException {

        String value = jsonObject.getString("refresh_token", null);

        if (value == null) {
            return null;
        }

        return new RefreshToken(value);
    }


    @Override
    public boolean equals(Object object) {

        return object instanceof RefreshToken &&
                this.toString().equals(object.toString());
    }
}
