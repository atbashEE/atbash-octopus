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
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * OAuth 2.0 Token error response.
 *
 * <p>Standard token errors:
 *
 * <ul>
 *     <li>{@link OAuth2Error#INVALID_REQUEST}
 *     <li>{@link OAuth2Error#INVALID_CLIENT}
 *     <li>{@link OAuth2Error#INVALID_GRANT}
 *     <li>{@link OAuth2Error#UNAUTHORIZED_CLIENT}
 *     <li>{@link OAuth2Error#UNSUPPORTED_GRANT_TYPE}
 *     <li>{@link OAuth2Error#INVALID_SCOPE}
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 *  "error": "invalid_request"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 5.2.
 * </ul>
 */
public class TokenErrorResponse extends TokenResponse implements ErrorResponse {


    /**
     * The standard OAuth 2.0 errors for an Access Token error response.
     */
    private static final Set<ErrorObject> STANDARD_ERRORS;


    static {
        Set<ErrorObject> errors = new HashSet<>();
        errors.add(OAuth2Error.INVALID_REQUEST);
        errors.add(OAuth2Error.INVALID_CLIENT);
        errors.add(OAuth2Error.INVALID_GRANT);
        errors.add(OAuth2Error.UNAUTHORIZED_CLIENT);
        errors.add(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
        errors.add(OAuth2Error.INVALID_SCOPE);
        STANDARD_ERRORS = Collections.unmodifiableSet(errors);
    }


    /**
     * Gets the standard OAuth 2.0 errors for an Access Token error
     * response.
     *
     * @return The standard errors, as a read-only set.
     */
    public static Set<ErrorObject> getStandardErrors() {

        return STANDARD_ERRORS;
    }


    /**
     * The error.
     */
    private final ErrorObject error;


    /**
     * Creates a new OAuth 2.0 Access Token error response. No OAuth 2.0
     * error is specified.
     */
    protected TokenErrorResponse() {

        error = null;
    }


    /**
     * Creates a new OAuth 2.0 Access Token error response.
     *
     * @param error The error. Should match one of the
     *              {@link #getStandardErrors standard errors} for a token
     *              error response. Must not be {@code null}.
     */
    public TokenErrorResponse(ErrorObject error) {

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


    /**
     * Returns the JSON object for this token error response.
     *
     * @return The JSON object for this token error response.
     */
    public JsonObject toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder();


        // No error?
        if (error == null) {
            return result.build();
        }

        if (error.getCode() != null) {
            result.add("error", error.getCode());
        } else {
            result.addNull("error");
        }

        if (error.getDescription() != null) {
            result.add("error_description", error.getDescription());
        }

        if (error.getURI() != null) {
            result.add("error_uri", error.getURI().toString());
        }

        return result.build();
    }


    @Override
    public HTTPResponse toHTTPResponse() {

        int statusCode = (error != null && error.getHTTPStatusCode() > 0) ?
                error.getHTTPStatusCode() : HTTPResponse.SC_BAD_REQUEST;

        HTTPResponse httpResponse = new HTTPResponse(statusCode);

        if (error == null) {
            return httpResponse;
        }

        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");

        httpResponse.setContent(toJSONObject().toString());

        return httpResponse;
    }


    /**
     * Parses an OAuth 2.0 Token Error response from the specified JSON
     * object.
     *
     * @param jsonObject The JSON object to parse. Its status code must not
     *                   be 200 (OK). Must not be {@code null}.
     * @return The token error response.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to an
     *                                  OAuth 2.0 Token Error response.
     */
    public static TokenErrorResponse parse(JsonObject jsonObject)
            throws OAuth2JSONParseException {

        // No error code?
        if (!jsonObject.containsKey("error")) {
            return new TokenErrorResponse();
        }

        ErrorObject error;

        try {
            // Parse code
            String code = jsonObject.getString("error");
            String description = jsonObject.getString("error_description");
            URI uri = JSONObjectUtils.getURI(jsonObject, "error_uri");

            error = new ErrorObject(code, description, HTTPResponse.SC_BAD_REQUEST, uri);

        } catch (java.text.ParseException e) {
            throw new OAuth2JSONParseException("Missing or invalid token error response parameter: " + e.getMessage(), e);
        }

        return new TokenErrorResponse(error);
    }


    /**
     * Parses an OAuth 2.0 Token Error response from the specified HTTP
     * response.
     *
     * @param httpResponse The HTTP response to parse. Its status code must
     *                     not be 200 (OK). Must not be {@code null}.
     * @return The token error response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to an
     *                                  OAuth 2.0 Token Error response.
     */
    public static TokenErrorResponse parse(HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        httpResponse.ensureStatusCodeNotOK();
        return new TokenErrorResponse(ErrorObject.parse(httpResponse));
    }
}
