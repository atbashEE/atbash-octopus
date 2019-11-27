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
 * Pushed authorisation response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Pushed Authorization Requests
 *         (draft-lodderstedt-oauth-par-01)
 * </ul>
 */
public abstract class PushedAuthorizationResponse implements Response {


    /**
     * Casts this response to a pushed authorisation success response.
     *
     * @return The pushed authorisation success response.
     */
    public PushedAuthorizationSuccessResponse toSuccessResponse() {

        return (PushedAuthorizationSuccessResponse) this;
    }


    /**
     * Casts this response to a pushed authorisation error response.
     *
     * @return The pushed authorisation error response.
     */
    public PushedAuthorizationErrorResponse toErrorResponse() {

        return (PushedAuthorizationErrorResponse) this;
    }


    /**
     * Parses a pushed authorisation response from the specified HTTP
     * response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The pushed authorisation success or error response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  pushed authorisation response.
     */
    public static PushedAuthorizationResponse parse(HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        if (httpResponse.getStatusCode() == HTTPResponse.SC_CREATED || httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
            return PushedAuthorizationSuccessResponse.parse(httpResponse);
        } else {
            return PushedAuthorizationErrorResponse.parse(httpResponse);
        }
    }
}
