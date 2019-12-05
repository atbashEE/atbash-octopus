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


import be.atbash.ee.oauth2.sdk.AuthorizationResponse;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.jarm.JARMUtils;
import be.atbash.ee.oauth2.sdk.jarm.JARMValidator;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URIUtils;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.util.StringUtils;

import java.net.URI;
import java.util.List;
import java.util.Map;


/**
 * Parser of OpenID Connect authentication response messages.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 3.1.2.5. and 3.1.2.6.
 *     <li>OAuth 2.0 (RFC 6749), section 3.1.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM).
 * </ul>
 */
public class AuthenticationResponseParser {


    /**
     * Parses an OpenID Connect authentication response which may be
     * JSON Web Token (JWT) secured.
     *
     * @param redirectURI The base redirection URI. Must not be
     *                    {@code null}.
     * @param params      The response parameters to parse. Must not be
     *                    {@code null}.
     * @return The OpenID Connect authentication success or error response.
     * @throws OAuth2JSONParseException If the parameters couldn't be parsed to an
     *                                  OpenID Connect authentication response, or if
     *                                  validation of the JWT response failed.
     */
    public static AuthenticationResponse parse(URI redirectURI,
                                               Map<String, List<String>> params,
                                               JARMValidator jarmValidator)
            throws OAuth2JSONParseException {

        Map<String, List<String>> workParams = params;
        String jwtResponseString = MultivaluedMapUtils.getFirstValue(params, "response");

        if (jarmValidator != null) {
            if (StringUtils.isEmpty(jwtResponseString)) {
                throw new OAuth2JSONParseException("Missing JWT-secured (JARM) authorization response parameter");
            }
            try {
                JWTClaimsSet jwtClaimsSet = jarmValidator.validate(jwtResponseString);
                workParams = JARMUtils.toMultiValuedStringParameters(jwtClaimsSet);
            } catch (Exception e) {
                throw new OAuth2JSONParseException("Invalid JWT-secured (JARM) authorization response: " + e.getMessage());
            }
        }

        if (StringUtils.hasText(MultivaluedMapUtils.getFirstValue(params, "error"))) {
            return AuthenticationErrorResponse.parse(redirectURI, params);
        } else if (StringUtils.hasText(MultivaluedMapUtils.getFirstValue(params, "response"))) {

            // JARM that wasn't validated, peek into JWT if signed only
            boolean likelyError = JARMUtils.impliesAuthorizationErrorResponse(jwtResponseString);
            if (likelyError) {
                return AuthenticationErrorResponse.parse(redirectURI, workParams);
            } else {
                return AuthenticationSuccessResponse.parse(redirectURI, workParams);
            }


        } else {
            return AuthenticationSuccessResponse.parse(redirectURI, params);
        }
    }


    /**
     * Parses an OpenID Connect authentication response.
     *
     * <p>Use a relative URI if the host, port and path details are not
     * known:
     *
     * <pre>
     * URI relUrl = new URI("https:///?code=Qcb0Orv1...&amp;state=af0ifjsldkj");
     * </pre>
     *
     * <p>Example URI:
     *
     * <pre>
     * https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
     * </pre>
     *
     * @param uri The URI to parse. Can be absolute or relative, with a
     *            fragment or query string containing the authentication
     *            response parameters. Must not be {@code null}.
     * @return The OpenID Connect authentication success or error response.
     * @throws OAuth2JSONParseException If the redirection URI couldn't be parsed to
     *                                  an OpenID Connect authentication response.
     */
    public static AuthenticationResponse parse(URI uri, JARMValidator jarmValidator)
            throws OAuth2JSONParseException {

        return parse(URIUtils.getBaseURI(uri), AuthorizationResponse.parseResponseParameters(uri), jarmValidator);

    }

    public static AuthenticationResponse parse(URI uri)
            throws OAuth2JSONParseException {

        return parse(URIUtils.getBaseURI(uri), AuthorizationResponse.parseResponseParameters(uri), null);
    }


    /**
     * Parses an OpenID Connect authentication response from the specified
     * initial HTTP 302 redirect response output at the authorisation
     * endpoint.
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
     * @return The OpenID Connect authentication response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to an
     *                                  OpenID Connect authentication response.
     */
    public static AuthenticationResponse parse(HTTPResponse httpResponse, JARMValidator jarmValidator)
            throws OAuth2JSONParseException {

        URI location = httpResponse.getLocation();

        if (location == null) {
            throw new OAuth2JSONParseException("Missing redirection URI / HTTP Location header");
        }

        return parse(location, jarmValidator);
    }

    public static AuthenticationResponse parse(HTTPResponse httpResponse)
            throws OAuth2JSONParseException {


        return parse(httpResponse, null);
    }


    /**
     * Parses an OpenID Connect authentication response from the specified
     * HTTP request at the client redirection (callback) URI. Applies to
     * the {@code query}, {@code fragment} and {@code form_post} response
     * modes.
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
     * @return The OpenID Connect authentication response.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to an
     *                                  OpenID Connect authentication response.
     * @see #parse(HTTPResponse)
     */
    public static AuthenticationResponse parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        return parse(httpRequest.getURI(), AuthorizationResponse.parseResponseParameters(httpRequest), null);
    }


    /**
     * Prevents public instantiation.
     */
    private AuthenticationResponseParser() {
    }
}
