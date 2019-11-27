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
 * Request object POST response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial-grade API - Part 2: Read and Write API Security Profile,
 *         section 7.
 *     <li>The OAuth 2.0 Authorization Framework: JWT Secured Authorization
 *         Request (JAR) (draft-ietf-oauth-jwsreq-17).
 * </ul>
 */
@Deprecated
// FIXME Remove Deprecated stuff
public abstract class RequestObjectPOSTResponse implements Response {


    /**
     * Casts this response to a request object POST success response.
     *
     * @return The request object POST success response.
     */
    public RequestObjectPOSTSuccessResponse toSuccessResponse() {

        return (RequestObjectPOSTSuccessResponse) this;
    }


    /**
     * Casts this response to a request object POST error response.
     *
     * @return The request object POST error response.
     */
    public RequestObjectPOSTErrorResponse toErrorResponse() {

        return (RequestObjectPOSTErrorResponse) this;
    }


    /**
     * Parses a request object POST response from the specified HTTP
     * response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The request object POST success or error response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  request object POST response.
     */
    public static RequestObjectPOSTResponse parse(HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        if (httpResponse.getStatusCode() == HTTPResponse.SC_CREATED || httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
            return RequestObjectPOSTSuccessResponse.parse(httpResponse);
        } else {
            return RequestObjectPOSTErrorResponse.parse(httpResponse);
        }
    }
}
