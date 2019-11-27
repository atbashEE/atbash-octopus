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


/**
 * Assertion grant. Used in access token requests with an assertion, such as a
 * SAML 2.0 assertion or JSON Web Token (JWT).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521), section 4.1.
 * </ul>
 */
public abstract class AssertionGrant extends AuthorizationGrant {


    private static final String MISSING_GRANT_TYPE_PARAM_MESSAGE = "Missing \"grant_type\" parameter";


    private static final String MISSING_ASSERTION_PARAM_MESSAGE = "Missing or empty \"assertion\" parameter";


    /**
     * Cached missing {@code grant_type} parameter exception.
     */
    protected static final OAuth2JSONParseException MISSING_GRANT_TYPE_PARAM_EXCEPTION
            = new OAuth2JSONParseException(MISSING_GRANT_TYPE_PARAM_MESSAGE,
            OAuth2Error.INVALID_REQUEST.appendDescription(": " + MISSING_GRANT_TYPE_PARAM_MESSAGE));


    /**
     * Caches missing {@code assertion} parameter exception.
     */
    protected static final OAuth2JSONParseException MISSING_ASSERTION_PARAM_EXCEPTION
            = new OAuth2JSONParseException(MISSING_ASSERTION_PARAM_MESSAGE,
            OAuth2Error.INVALID_REQUEST.appendDescription(": " + MISSING_ASSERTION_PARAM_MESSAGE));


    /**
     * Creates a new assertion-based authorisation grant.
     *
     * @param type The authorisation grant type. Must not be {@code null}.
     */
    protected AssertionGrant(GrantType type) {

        super(type);
    }


    /**
     * Gets the assertion.
     *
     * @return The assertion as a string.
     */
    public abstract String getAssertion();
}
