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
 * Request object POST error response.
 *
 * <p>Example request object POST error response indicating an invalid JWS
 * signature:
 *
 * <pre>
 * HTTP/1.1 401 Unauthorized
 * Date: Tue, 2 May 2017 15:22:31 GMT
 * </pre>
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
public final class RequestObjectPOSTErrorResponse extends RequestObjectPOSTResponse implements ErrorResponse {


    /**
     * Holds the HTTP status code.
     */
    private final ErrorObject errorObject;


    /**
     * Creates a new request object POST error response.
     *
     * @param httpStatusCode The HTTP status code. Should be other than
     *                       2xx.
     */
    public RequestObjectPOSTErrorResponse(final int httpStatusCode) {
        errorObject = new ErrorObject(null, null, httpStatusCode);
    }


    public int getHTTPStatusCode() {
        return errorObject.getHTTPStatusCode();
    }


    @Override
    public ErrorObject getErrorObject() {
        return errorObject;
    }


    @Override
    public boolean indicatesSuccess() {
        return false;
    }


    @Override
    public HTTPResponse toHTTPResponse() {
        return new HTTPResponse(getHTTPStatusCode());
    }


    /**
     * Parses a request object POST error response from the specified
     * HTTP response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The request object POST error response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  request object POST error response.
     */
    public static RequestObjectPOSTErrorResponse parse(final HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        if (httpResponse.getStatusCode() >= 200 && httpResponse.getStatusCode() <= 299) {
            throw new OAuth2JSONParseException("Unexpected HTTP status code, must not be 2xx");
        }

        return new RequestObjectPOSTErrorResponse(httpResponse.getStatusCode());
    }
}
