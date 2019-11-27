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
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URIUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.util.StringUtils;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
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
    private final State state;


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

        this.state = null;

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

        final ResponseMode rm = impliedResponseMode();

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
     * Casts this response to an authorisation success response.
     *
     * @return The authorisation success response.
     */
    public AuthorizationSuccessResponse toSuccessResponse() {

        return (AuthorizationSuccessResponse) this;
    }


    /**
     * Casts this response to an authorisation error response.
     *
     * @return The authorisation error response.
     */
    public AuthorizationErrorResponse toErrorResponse() {

        return (AuthorizationErrorResponse) this;
    }

    /**
     * Parses an authorisation response which may be JSON Web Token (JWT)
     * secured.
     *
     * @param redirectURI The base redirection URI. Must not be
     *                    {@code null}.
     * @param params      The response parameters to parse. Must not be
     *                    {@code null}.
     * @return The authorisation success or error response.
     * @throws OAuth2JSONParseException If the parameters couldn't be parsed to an
     *                                  authorisation success or error response, or
     *                                  if validation of the JWT secured response
     *                                  failed.
     */
    public static AuthorizationResponse parse(URI redirectURI,
                                              Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        Map<String, List<String>> workParams = params;

        String jwtResponseString = MultivaluedMapUtils.getFirstValue(params, "response");


        if (StringUtils.hasText(MultivaluedMapUtils.getFirstValue(workParams, "error"))) {
            return AuthorizationErrorResponse.parse(redirectURI, workParams);
        } else if (StringUtils.hasText(jwtResponseString)) {
            // JARM that wasn't validated, peek into JWT if signed only
            throw new IllegalArgumentException("Not implemented yet");  // TODO
            /*
            boolean likelyError = JARMUtils.impliesAuthorizationErrorResponse(jwtResponseString);
            if (likelyError) {
                return AuthorizationErrorResponse.parse(redirectURI, workParams);
            } else {
                return AuthorizationSuccessResponse.parse(redirectURI, workParams);
            }

             */

        } else {
            return AuthorizationSuccessResponse.parse(redirectURI, workParams);
        }
    }

    /**
     * Parses an authorisation response.
     *
     * <p>Use a relative URI if the host, port and path details are not
     * known:
     *
     * <pre>
     * URI relUrl = new URI("https:///?code=Qcb0Orv1...&amp;state=af0ifjsldkj");
     * </pre>
     *
     * @param uri The URI to parse. Can be absolute or relative, with a
     *            fragment or query string containing the authorisation
     *            response parameters. Must not be {@code null}.
     * @return The authorisation success or error response.
     * @throws OAuth2JSONParseException If no authorisation response parameters were
     *                                  found in the URL.
     */
    public static AuthorizationResponse parse(URI uri)
            throws OAuth2JSONParseException {

        return parse(URIUtils.getBaseURI(uri), parseResponseParameters(uri));
    }


    /**
     * Parses an authorisation response from the specified initial HTTP 302
     * redirect response output at the authorisation endpoint.
     *
     * <p>Example HTTP response (authorisation success):
     *
     * <pre>
     * HTTP/1.1 302 Found
     * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
     * </pre>
     *
     * @param httpResponse The HTTP response to parse. Must not be
     *                     {@code null}.
     * @return The authorisation response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to an
     *                                  authorisation response.
     * @see #parse(HTTPRequest)
     */
    public static AuthorizationResponse parse(HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        URI location = httpResponse.getLocation();

        if (location == null) {
            throw new OAuth2JSONParseException("Missing redirection URI / HTTP Location header");
        }

        return parse(location);
    }


    /**
     * Parses an authorisation response from the specified HTTP request at
     * the client redirection (callback) URI. Applies to the {@code query},
     * {@code fragment} and {@code form_post} response modes.
     *
     * <p>Example HTTP request (authorisation success):
     *
     * <pre>
     * GET /cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz HTTP/1.1
     * Host: client.example.com
     * </pre>
     *
     * @param httpRequest The HTTP request to parse. Must not be
     *                    {@code null}.
     * @return The authorisation response.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to an
     *                                  authorisation response.
     * @see #parse(HTTPResponse)
     */
    public static AuthorizationResponse parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        return parse(httpRequest.getURI(), parseResponseParameters(httpRequest));
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