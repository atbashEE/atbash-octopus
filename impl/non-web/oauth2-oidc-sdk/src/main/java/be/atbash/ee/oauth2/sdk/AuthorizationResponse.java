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
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.jarm.JARMUtils;
import be.atbash.ee.oauth2.sdk.jarm.JARMValidator;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URIUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashUnexpectedException;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.List;
import java.util.Map;


/**
 * The base abstract class for authorisation success and error responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 3.1.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM).
 * </ul>
 */
public abstract class AuthorizationResponse implements Response {


    /**
     * The base redirection URI.
     */
    private final URI redirectURI;


    /**
     * The optional state parameter to be echoed back to the client.
     */
    private State state;


    /**
     * For a JWT-secured response.
     */
    private final JWT jwtResponse;


    /**
     * The optional explicit response mode.
     */
    private final ResponseMode rm;


    /**
     * Creates a new authorisation response.
     *
     * @param redirectURI The base redirection URI. Must not be
     *                    {@code null}.
     * @param state       The state, {@code null} if not requested.
     * @param rm          The response mode, {@code null} if not specified.
     */
    protected AuthorizationResponse(URI redirectURI, State state, ResponseMode rm) {

        if (redirectURI == null) {
            throw new IllegalArgumentException("The redirection URI must not be null");
        }

        this.redirectURI = redirectURI;

        jwtResponse = null;

        this.state = state;

        this.rm = rm;
    }


    /**
     * Creates a new JSON Web Token (JWT) secured authorisation response.
     *
     * @param redirectURI The base redirection URI. Must not be
     *                    {@code null}.
     * @param jwtResponse The JWT response. Must not be {@code null}.
     * @param rm          The response mode, {@code null} if not specified.
     */
    protected AuthorizationResponse(URI redirectURI, JWT jwtResponse, ResponseMode rm) {

        if (redirectURI == null) {
            throw new IllegalArgumentException("The redirection URI must not be null");
        }

        this.redirectURI = redirectURI;

        if (jwtResponse == null) {
            throw new IllegalArgumentException("The JWT response must not be null");
        }

        this.jwtResponse = jwtResponse;

        try {
            JWTClaimsSet jwtClaimsSet = jwtResponse.getJWTClaimsSet();
            if (jwtClaimsSet.getClaim("state") != null) {
                this.state = new State(jwtClaimsSet.getStringClaim("state"));
            }
        } catch (ParseException e) {
            // Should not happen as payload is already validated
            throw new AtbashUnexpectedException(e);
        }

        this.rm = rm;
    }


    /**
     * Returns the base redirection URI.
     *
     * @return The base redirection URI (without the appended error
     * response parameters).
     */
    public URI getRedirectionURI() {

        return redirectURI;
    }


    /**
     * Returns the optional state.
     *
     * @return The state, {@code null} if not requested or if the response
     * is JWT-secured in which case the state parameter may be
     * included as a JWT claim.
     */
    public State getState() {

        return state;
    }


    /**
     * Returns the JSON Web Token (JWT) secured response.
     *
     * @return The JWT-secured response, {@code null} for a regular
     * authorisation response.
     */
    public JWT getJWTResponse() {

        return jwtResponse;
    }


    /**
     * Returns the optional explicit response mode.
     *
     * @return The response mode, {@code null} if not specified.
     */
    public ResponseMode getResponseMode() {

        return rm;
    }


    /**
     * Determines the implied response mode.
     *
     * @return The implied response mode.
     */
    public abstract ResponseMode impliedResponseMode();


    /**
     * Returns the parameters of this authorisation response.
     *
     * <p>Example parameters (authorisation success):
     *
     * <pre>
     * access_token = 2YotnFZFEjr1zCsicMWpAA
     * state = xyz
     * token_type = example
     * expires_in = 3600
     * </pre>
     *
     * @return The parameters as a map.
     */
    public abstract Map<String, List<String>> toParameters();


    /**
     * Returns a URI representation (redirection URI + fragment / query
     * string) of this authorisation response.
     *
     * <p>Example URI:
     *
     * <pre>
     * http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
     * &amp;state=xyz
     * &amp;token_type=example
     * &amp;expires_in=3600
     * </pre>
     *
     * @return A URI representation of this authorisation response.
     */
    public URI toURI() {

        ResponseMode rm = impliedResponseMode();

        StringBuilder sb = new StringBuilder(getRedirectionURI().toString());

        if (ResponseMode.QUERY.equals(rm) || ResponseMode.QUERY_JWT.equals(rm)) {
            if (StringUtils.isEmpty(getRedirectionURI().getRawQuery())) {
                sb.append('?');
            } else {
                // The original redirect_uri may contain query params,
                // see http://tools.ietf.org/html/rfc6749#section-3.1.2
                sb.append('&');
            }
        } else if (ResponseMode.FRAGMENT.equals(rm) || ResponseMode.FRAGMENT_JWT.equals(rm)) {
            sb.append('#');
        } else {
            throw new SerializeException("The (implied) response mode must be query or fragment");
        }

        sb.append(URLUtils.serializeParameters(toParameters()));

        try {
            return new URI(sb.toString());

        } catch (URISyntaxException e) {

            throw new SerializeException("Couldn't serialize response: " + e.getMessage(), e);
        }
    }


    /**
     * Returns an HTTP response for this authorisation response. Applies to
     * the {@code query} or {@code fragment} response mode using HTTP 302
     * redirection.
     *
     * <p>Example HTTP response (authorisation success):
     *
     * <pre>
     * HTTP/1.1 302 Found
     * Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
     * &amp;state=xyz
     * &amp;token_type=example
     * &amp;expires_in=3600
     * </pre>
     *
     * @return An HTTP response for this authorisation response.
     * @see #toHTTPRequest()
     */
    @Override
    public HTTPResponse toHTTPResponse() {

        if (ResponseMode.FORM_POST.equals(rm)) {
            throw new SerializeException("The response mode must not be form_post");
        }

        HTTPResponse response = new HTTPResponse(HTTPResponse.SC_FOUND);
        response.setLocation(toURI());
        return response;
    }


    /**
     * Returns an HTTP request for this authorisation response. Applies to
     * the {@code form_post} response mode.
     *
     * <p>Example HTTP request (authorisation success):
     *
     * <pre>
     * GET /cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz HTTP/1.1
     * Host: client.example.com
     * </pre>
     *
     * @return An HTTP request for this authorisation response.
     * @see #toHTTPResponse()
     */
    public HTTPRequest toHTTPRequest() {

        if (!ResponseMode.FORM_POST.equals(rm)) {
            throw new SerializeException("The response mode must be form_post");
        }

        // Use HTTP POST
        HTTPRequest request;

        try {
            request = new HTTPRequest(HTTPRequest.Method.POST, redirectURI.toURL());

        } catch (MalformedURLException e) {
            throw new SerializeException(e.getMessage(), e);
        }

        request.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        request.setQuery(URLUtils.serializeParameters(toParameters()));
        return request;
    }

    /**
     * Parses the relevant authorisation response parameters. This method
     * is intended for internal SDK usage only.
     *
     * @param uri The URI to parse its query or fragment parameters. Must
     *            not be {@code null}.
     * @return The authorisation response parameters.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static Map<String, List<String>> parseResponseParameters(URI uri)
            throws OAuth2JSONParseException {

        if (uri.getRawFragment() != null) {
            return URLUtils.parseParameters(uri.getRawFragment());
        } else if (uri.getRawQuery() != null) {
            return URLUtils.parseParameters(uri.getRawQuery());
        } else {
            throw new OAuth2JSONParseException("Missing URI fragment or query string");
        }
    }


    /**
     * Parses the relevant authorisation response parameters. This method
     * is intended for internal SDK usage only.
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The authorisation response parameters.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static Map<String, List<String>> parseResponseParameters(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        if (httpRequest.getQuery() != null) {
            // For query string and form_post response mode
            return URLUtils.parseParameters(httpRequest.getQuery());
        } else if (httpRequest.getFragment() != null) {
            // For fragment response mode (never available in actual HTTP request from browser)
            return URLUtils.parseParameters(httpRequest.getFragment());
        } else {
            throw new OAuth2JSONParseException("Missing URI fragment, query string or post body");
        }
    }
}