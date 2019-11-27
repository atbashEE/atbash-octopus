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


import be.atbash.ee.oauth2.sdk.pkce.CodeVerifier;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;


/**
 * Authorisation code grant. Used in access token requests with an
 * authorisation code.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 4.1.3.
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636).
 * </ul>
 */
public class AuthorizationCodeGrant extends AuthorizationGrant {


    /**
     * The grant type.
     */
    public static final GrantType GRANT_TYPE = GrantType.AUTHORIZATION_CODE;


    /**
     * The authorisation code received from the authorisation server.
     */
    private final AuthorizationCode code;


    /**
     * The conditionally required redirection URI in the initial
     * authorisation request.
     */
    private final URI redirectURI;


    /**
     * The optional authorisation code verifier for PKCE.
     */
    private final CodeVerifier codeVerifier;


    /**
     * Creates a new authorisation code grant.
     *
     * @param code        The authorisation code. Must not be {@code null}.
     * @param redirectURI The redirection URI of the original authorisation
     *                    request. Required if the {redirect_uri}
     *                    parameter was included in the authorisation
     *                    request, else {@code null}.
     */
    public AuthorizationCodeGrant(AuthorizationCode code,
                                  URI redirectURI) {

        this(code, redirectURI, null);
    }


    /**
     * Creates a new authorisation code grant.
     *
     * @param code         The authorisation code. Must not be {@code null}.
     * @param redirectURI  The redirection URI of the original
     *                     authorisation request. Required if the
     *                     {redirect_uri} parameter was included in the
     *                     authorisation request, else {@code null}.
     * @param codeVerifier The authorisation code verifier for PKCE,
     *                     {@code null} if not specified.
     */
    public AuthorizationCodeGrant(AuthorizationCode code,
                                  URI redirectURI,
                                  CodeVerifier codeVerifier) {

        super(GRANT_TYPE);

        if (code == null) {
            throw new IllegalArgumentException("The authorisation code must not be null");
        }

        this.code = code;

        this.redirectURI = redirectURI;

        this.codeVerifier = codeVerifier;
    }


    /**
     * Gets the authorisation code.
     *
     * @return The authorisation code.
     */
    public AuthorizationCode getAuthorizationCode() {

        return code;
    }


    /**
     * Gets the redirection URI of the original authorisation request.
     *
     * @return The redirection URI, {@code null} if the
     * {@code redirect_uri} parameter was not included in the
     * original authorisation request.
     */
    public URI getRedirectionURI() {

        return redirectURI;
    }


    /**
     * Gets the authorisation code verifier for PKCE.
     *
     * @return The authorisation code verifier, {@code null} if not
     * specified.
     */
    public CodeVerifier getCodeVerifier() {

        return codeVerifier;
    }


    @Override
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = new LinkedHashMap<>();
        params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
        params.put("code", Collections.singletonList(code.getValue()));

        if (redirectURI != null) {
            params.put("redirect_uri", Collections.singletonList(redirectURI.toString()));
        }

        if (codeVerifier != null) {
            params.put("code_verifier", Collections.singletonList(codeVerifier.getValue()));
        }

        return params;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AuthorizationCodeGrant)) {
            return false;
        }

        AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant) o;

        if (!code.equals(codeGrant.code)) {
            return false;
        }
        if (!Objects.equals(redirectURI, codeGrant.redirectURI)) {
            return false;
        }
        if (codeVerifier != null && codeGrant.codeVerifier != null) {
            return codeVerifier.getValue().equals(codeGrant.codeVerifier.getValue());
        }
        return codeVerifier == null && codeGrant.codeVerifier == null;

    }


    @Override
    public int hashCode() {
        int result = code.hashCode();
        result = 31 * result + (redirectURI != null ? redirectURI.hashCode() : 0);
        result = 31 * result + (codeVerifier != null ? codeVerifier.hashCode() : 0);
        return result;
    }


    /**
     * Parses an authorisation code grant from the specified request body
     * parameters.
     *
     * <p>Example:
     *
     * <pre>
     * grant_type=authorization_code
     * code=SplxlOBeZQQYbYS6WxSbIA
     * redirect_uri=https://Fclient.example.com/cb
     * </pre>
     *
     * @param params The parameters.
     * @return The authorisation code grant.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static AuthorizationCodeGrant parse(Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        // Parse grant type
        String grantTypeString = MultivaluedMapUtils.getFirstValue(params, "grant_type");

        if (grantTypeString == null) {
            String msg = "Missing \"grant_type\" parameter";
            throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
        }

        if (!GrantType.parse(grantTypeString).equals(GRANT_TYPE)) {
            String msg = "The \"grant_type\" must be \"" + GRANT_TYPE + "\"";
            throw new OAuth2JSONParseException(msg, OAuth2Error.UNSUPPORTED_GRANT_TYPE.appendDescription(": " + msg));
        }

        // Parse authorisation code
        String codeString = MultivaluedMapUtils.getFirstValue(params, "code");

        if (codeString == null || codeString.trim().isEmpty()) {
            String msg = "Missing or empty \"code\" parameter";
            throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
        }

        AuthorizationCode code = new AuthorizationCode(codeString);

        // Parse optional redirection URI
        String redirectURIString = MultivaluedMapUtils.getFirstValue(params, "redirect_uri");

        URI redirectURI = null;

        if (redirectURIString != null) {
            try {
                redirectURI = new URI(redirectURIString);
            } catch (URISyntaxException e) {
                String msg = "Invalid \"redirect_uri\" parameter: " + e.getMessage();
                throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg), e);
            }
        }


        // Parse optional code verifier
        String codeVerifierString = MultivaluedMapUtils.getFirstValue(params, "code_verifier");

        CodeVerifier codeVerifier = null;

        if (StringUtils.hasText(codeVerifierString)) {

            try {
                codeVerifier = new CodeVerifier(codeVerifierString);  // FIXME Is this correct String <-> Byte ARray sinceSecret has Changed!!
            } catch (IllegalArgumentException e) {
                // Illegal code verifier
                throw new OAuth2JSONParseException(e.getMessage(), e);
            }
        }

        return new AuthorizationCodeGrant(code, redirectURI, codeVerifier);
    }
}
