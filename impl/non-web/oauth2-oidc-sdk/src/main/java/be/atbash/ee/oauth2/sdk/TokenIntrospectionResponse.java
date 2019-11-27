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


import be.atbash.ee.oauth2.sdk.http.HTTPResponse;

/**
 * Token introspection response. This is the base abstract class for token
 * introspection success and error responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Introspection (RFC 7662).
 * </ul>
 */
public abstract class TokenIntrospectionResponse implements Response {


    /**
     * Casts this response to a token introspection success response.
     *
     * @return The token introspection success response.
     */
    public TokenIntrospectionSuccessResponse toSuccessResponse() {

        return (TokenIntrospectionSuccessResponse) this;
    }


    /**
     * Casts this response to a token introspection error response.
     *
     * @return The token introspection error response.
     */
    public TokenIntrospectionErrorResponse toErrorResponse() {

        return (TokenIntrospectionErrorResponse) this;
    }


    /**
     * Parses a token introspection response from the specified HTTP
     * response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The token introspection success or error response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  token introspection response.
     */
    public static TokenIntrospectionResponse parse(HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        if (httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
            return TokenIntrospectionSuccessResponse.parse(httpResponse);
        } else {
            return TokenIntrospectionErrorResponse.parse(httpResponse);
        }
    }
}
