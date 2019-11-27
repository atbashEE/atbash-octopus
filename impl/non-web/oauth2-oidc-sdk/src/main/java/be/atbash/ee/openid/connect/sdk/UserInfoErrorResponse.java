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


import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.ee.oauth2.sdk.ErrorResponse;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.BearerTokenError;
import be.atbash.util.StringUtils;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * UserInfo error response.
 *
 * <p>Standard OAuth 2.0 Bearer Token errors:
 *
 * <ul>
 *     <li>{@link BearerTokenError#MISSING_TOKEN}
 *     <li>{@link BearerTokenError#INVALID_REQUEST}
 *     <li>{@link BearerTokenError#INVALID_TOKEN}
 *     <li>{@link BearerTokenError#INSUFFICIENT_SCOPE}
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 401 Unauthorized
 * WWW-Authenticate: Bearer realm="example.com",
 *                   error="invalid_token",
 *                   error_description="The access token expired"
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 5.3.3.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750), section 3.1.
 * </ul>
 */
public class UserInfoErrorResponse
        extends UserInfoResponse
        implements ErrorResponse {


    /**
     * Gets the standard errors for a UserInfo error response.
     *
     * @return The standard errors, as a read-only set.
     */
    public static Set<BearerTokenError> getStandardErrors() {

        Set<BearerTokenError> stdErrors = new HashSet<>();
        stdErrors.add(BearerTokenError.MISSING_TOKEN);
        stdErrors.add(BearerTokenError.INVALID_REQUEST);
        stdErrors.add(BearerTokenError.INVALID_TOKEN);
        stdErrors.add(BearerTokenError.INSUFFICIENT_SCOPE);

        return Collections.unmodifiableSet(stdErrors);
    }


    /**
     * The underlying error.
     */
    private final ErrorObject error;


    /**
     * Creates a new UserInfo error response. No OAuth 2.0 bearer token
     * error / general error object is specified.
     */
    private UserInfoErrorResponse() {

        error = null;
    }


    /**
     * Creates a new UserInfo error response indicating a bearer token
     * error.
     *
     * @param error The OAuth 2.0 bearer token error. Should match one of
     *              the {@link #getStandardErrors standard errors} for a
     *              UserInfo error response. Must not be {@code null}.
     */
    public UserInfoErrorResponse(BearerTokenError error) {

        this((ErrorObject) error);
    }


    /**
     * Creates a new UserInfo error response indicating a general error.
     *
     * @param error The error. Must not be {@code null}.
     */
    public UserInfoErrorResponse(ErrorObject error) {

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
     * Returns the HTTP response for this UserInfo error response.
     *
     * <p>Example HTTP response:
     *
     * <pre>
     * HTTP/1.1 401 Unauthorized
     * WWW-Authenticate: Bearer realm="example.com",
     *                   error="invalid_token",
     *                   error_description="The access token expired"
     * </pre>
     *
     * @return The HTTP response matching this UserInfo error response.
     */
    @Override
    public HTTPResponse toHTTPResponse() {

        HTTPResponse httpResponse;

        if (error != null && error.getHTTPStatusCode() > 0) {
            httpResponse = new HTTPResponse(error.getHTTPStatusCode());
        } else {
            httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
        }

        // Add the WWW-Authenticate header
        if (error instanceof BearerTokenError) {
            httpResponse.setWWWAuthenticate(((BearerTokenError) error).toWWWAuthenticateHeader());
        } else if (error != null) {
            httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
            httpResponse.setContent(error.toJSONObject().toString());
        }

        return httpResponse;
    }


    /**
     * Parses a UserInfo error response from the specified HTTP response
     * {@code WWW-Authenticate} header.
     *
     * @param wwwAuth The {@code WWW-Authenticate} header value to parse.
     *                Must not be {@code null}.
     * @return The UserInfo error response.
     * @throws OAuth2JSONParseException If the {@code WWW-Authenticate} header value
     *                                  couldn't be parsed to a UserInfo error
     *                                  response.
     */
    public static UserInfoErrorResponse parse(String wwwAuth)
            throws OAuth2JSONParseException {

        BearerTokenError error = BearerTokenError.parse(wwwAuth);

        return new UserInfoErrorResponse(error);
    }


    /**
     * Parses a UserInfo error response from the specified HTTP response.
     *
     * <p>Note: The HTTP status code is not checked for matching the error
     * code semantics.
     *
     * @param httpResponse The HTTP response to parse. Its status code must
     *                     not be 200 (OK). Must not be {@code null}.
     * @return The UserInfo error response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  UserInfo error response.
     */
    public static UserInfoErrorResponse parse(HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        httpResponse.ensureStatusCodeNotOK();

        String wwwAuth = httpResponse.getWWWAuthenticate();

        if (StringUtils.hasText(wwwAuth)) {
            // Bearer token error?
            return parse(wwwAuth);
        }

        // Other error?
        return new UserInfoErrorResponse(ErrorObject.parse(httpResponse));
    }
}
