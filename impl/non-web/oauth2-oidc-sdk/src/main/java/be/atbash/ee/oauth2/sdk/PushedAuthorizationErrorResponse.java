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


import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;

/**
 * Pushed authorisation error response.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json
 * Cache-Control: no-cache, no-store
 *
 * {
 *  "error ": "invalid_request",
 *  "error_description" : "The redirect_uri is not valid for the given client"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Pushed Authorization Requests
 *         (draft-lodderstedt-oauth-par-01)
 * </ul>
 */
public class PushedAuthorizationErrorResponse extends PushedAuthorizationResponse implements ErrorResponse {


    /**
     * The error.
     */
    private final ErrorObject error;


    /**
     * Creates a new pushed authorisation error response.
     *
     * @param error The error. Must not be {@code null}.
     */
    public PushedAuthorizationErrorResponse(ErrorObject error) {

        if (error == null) {
            throw new IllegalArgumentException("The error must not be null");
        }

        this.error = error;
    }


    @Override
    public boolean indicatesSuccess() {
        return false;
    }


    @Override
    public ErrorObject getErrorObject() {
        return error;
    }


    @Override
    public HTTPResponse toHTTPResponse() {

        int statusCode = (error.getHTTPStatusCode() > 0) ? error.getHTTPStatusCode() : HTTPResponse.SC_BAD_REQUEST;
        HTTPResponse httpResponse = new HTTPResponse(statusCode);
        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");

        if (getErrorObject().getCode() != null) {
            httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
            httpResponse.setContent(getErrorObject().toJSONObject().toString());
        }

        return httpResponse;
    }


    /**
     * Parses a pushed authorisation error response from the specified HTTP
     * response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The pushed authorisation error response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  pushed authorisation error response.
     */
    public static PushedAuthorizationErrorResponse parse(HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        int statusCode = httpResponse.getStatusCode();

        if (statusCode == HTTPResponse.SC_CREATED || statusCode == HTTPResponse.SC_OK) {
            throw new OAuth2JSONParseException("The HTTP status code must be other than 201 and 200");
        }

        ErrorObject errorObject;
        if (httpResponse.getContentType() != null && CommonContentTypes.APPLICATION_JSON.getBaseType().equals(httpResponse.getContentType().getBaseType())) {
            errorObject = ErrorObject.parse(httpResponse.getContentAsJSONObject());
        } else {
            errorObject = new ErrorObject(null);
        }

        return new PushedAuthorizationErrorResponse(errorObject);
    }
}
