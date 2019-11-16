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
package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.ee.oauth2.sdk.ErrorResponse;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.BearerTokenError;
import be.atbash.util.StringUtils;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * Client registration error response.
 *
 * <p>Standard errors:
 *
 * <ul>
 *     <li>OAuth 2.0 Bearer Token errors:
 *         <ul>
 *             <li>{@link BearerTokenError#MISSING_TOKEN}
 *             <li>{@link BearerTokenError#INVALID_REQUEST}
 *             <li>{@link BearerTokenError#INVALID_TOKEN}
 *             <li>{@link BearerTokenError#INSUFFICIENT_SCOPE}
 *          </ul>
 *     <li>OpenID Connect specific errors:
 *         <ul>
 *             <li>{@link RegistrationError#INVALID_REDIRECT_URI}
 *             <li>{@link RegistrationError#INVALID_CLIENT_METADATA}
 *             <li>{@link RegistrationError#INVALID_SOFTWARE_STATEMENT}
 *             <li>{@link RegistrationError#UNAPPROVED_SOFTWARE_STATEMENT}
 *         </ul>
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
 *  "error":"invalid_redirect_uri",
 *  "error_description":"The redirection URI of http://sketchy.example.com is not allowed for this server."
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         3.2.2.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750), section 3.1.
 * </ul>
 */
public class ClientRegistrationErrorResponse
        extends ClientRegistrationResponse
        implements ErrorResponse {


    /**
     * Gets the standard errors for a client registration error response.
     *
     * @return The standard errors, as a read-only set.
     */
    public static Set<ErrorObject> getStandardErrors() {

        Set<ErrorObject> stdErrors = new HashSet<>();
        stdErrors.add(BearerTokenError.MISSING_TOKEN);
        stdErrors.add(BearerTokenError.INVALID_REQUEST);
        stdErrors.add(BearerTokenError.INVALID_TOKEN);
        stdErrors.add(BearerTokenError.INSUFFICIENT_SCOPE);
        stdErrors.add(RegistrationError.INVALID_REDIRECT_URI);
        stdErrors.add(RegistrationError.INVALID_CLIENT_METADATA);
        stdErrors.add(RegistrationError.INVALID_SOFTWARE_STATEMENT);
        stdErrors.add(RegistrationError.UNAPPROVED_SOFTWARE_STATEMENT);

        return Collections.unmodifiableSet(stdErrors);
    }


    /**
     * The underlying error.
     */
    private final ErrorObject error;


    /**
     * Creates a new client registration error response.
     *
     * @param error The error. Should match one of the
     *              {@link #getStandardErrors standard errors} for a client
     *              registration error response. Must not be {@code null}.
     */
    public ClientRegistrationErrorResponse(final ErrorObject error) {

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
     * Returns the HTTP response for this client registration error
     * response.
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
     *  "error":"invalid_redirect_uri",
     *  "error_description":"The redirection URI of http://sketchy.example.com is not allowed for this server."
     * }
     * </pre>
     *
     * @return The HTTP response.
     */
    @Override
    public HTTPResponse toHTTPResponse() {

        HTTPResponse httpResponse;

        if (error.getHTTPStatusCode() > 0) {
            httpResponse = new HTTPResponse(error.getHTTPStatusCode());
        } else {
            httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
        }

        // Add the WWW-Authenticate header
        if (error instanceof BearerTokenError) {

            BearerTokenError bte = (BearerTokenError) error;

            httpResponse.setWWWAuthenticate(bte.toWWWAuthenticateHeader());

        } else {
            JsonObjectBuilder jsonObject = Json.createObjectBuilder();

            if (error.getCode() != null) {
                jsonObject.add("error", error.getCode());
            }

            if (error.getDescription() != null) {
                jsonObject.add("error_description", error.getDescription());
            }

            httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
            // FIXME Should be done by ErrorObject itself (the To Json)
            httpResponse.setContent(jsonObject.build().toString());
        }

        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");

        return httpResponse;
    }


    /**
     * Parses a client registration error response from the specified HTTP
     * response.
     *
     * <p>Note: The HTTP status code is not checked for matching the error
     * code semantics.
     *
     * @param httpResponse The HTTP response to parse. Its status code must
     *                     not be 200 (OK). Must not be {@code null}.
     * @return The client registration error response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  client registration error response.
     */
    public static ClientRegistrationErrorResponse parse(final HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        httpResponse.ensureStatusCodeNotOK();

        ErrorObject error;

        String wwwAuth = httpResponse.getWWWAuthenticate();

        if (StringUtils.hasText(wwwAuth)) {
            error = BearerTokenError.parse(wwwAuth);
        } else {
            error = ErrorObject.parse(httpResponse);
        }

        return new ClientRegistrationErrorResponse(error);
    }
}