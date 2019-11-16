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


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.TokenErrorResponse;
import be.atbash.ee.oauth2.sdk.TokenResponse;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;

import javax.json.JsonObject;


/**
 * Parser of OpenID Connect token endpoint response messages.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 3.1.3.3 and 3.1.3.4.
 * </ul>
 */
public final class OIDCTokenResponseParser {


    /**
     * Parses an OpenID Connect token response or token error response from
     * the specified JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The OpenID Connect token response or token error response.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to a
     *                                  token response.
     */
    public static TokenResponse parse(final JsonObject jsonObject)
            throws OAuth2JSONParseException {

        if (jsonObject.containsKey("error")) {
            return TokenErrorResponse.parse(jsonObject);
        } else {
            return OIDCTokenResponse.parse(jsonObject);
        }
    }


    /**
     * Parses an OpenID Connect token response or token error response from
     * the specified HTTP response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The OpenID Connect token response or token error response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  token response.
     */
    public static TokenResponse parse(final HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        if (httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
            return OIDCTokenResponse.parse(httpResponse);
        } else {
            return TokenErrorResponse.parse(httpResponse);
        }
    }


    /**
     * Prevents public instantiation.
     */
    private OIDCTokenResponseParser() {
    }
}
