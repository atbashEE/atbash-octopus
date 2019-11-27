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


import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * SAML 2.0 bearer grant. Used in access token requests with a SAML 2.0 bearer
 * assertion.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521), section 4.1.
 *     <li>SAML 2.0 Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7522), section-2.1.
 * </ul>
 */
public class SAML2BearerGrant extends AssertionGrant {


    /**
     * The grant type.
     */
    public static final GrantType GRANT_TYPE = GrantType.SAML2_BEARER;


    /**
     * Cached {@code unsupported_grant_type} exception.
     */
    private static final OAuth2JSONParseException UNSUPPORTED_GRANT_TYPE_EXCEPTION
            = new OAuth2JSONParseException("The \"grant_type\" must be " + GRANT_TYPE, OAuth2Error.UNSUPPORTED_GRANT_TYPE);


    /**
     * The SAML 2.0 assertion.
     */
    private final Base64URLValue assertion;


    /**
     * Creates a new SAML 2.0 bearer assertion grant.
     *
     * @param assertion The SAML 2.0 bearer assertion. Must not be
     *                  {@code null}.
     */
    public SAML2BearerGrant(Base64URLValue assertion) {

        super(GRANT_TYPE);

        if (assertion == null) {
            throw new IllegalArgumentException("The SAML 2.0 bearer assertion must not be null");
        }

        this.assertion = assertion;
    }


    /**
     * Gets the SAML 2.0 bearer assertion.
     *
     * @return The SAML 2.0 bearer assertion.
     */
    public Base64URLValue getSAML2Assertion() {

        return assertion;
    }


    @Override
    public String getAssertion() {

        return assertion.toString();
    }


    @Override
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = new LinkedHashMap<>();
        params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
        params.put("assertion", Collections.singletonList(assertion.toString()));
        return params;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        SAML2BearerGrant that = (SAML2BearerGrant) o;

        return assertion.equals(that.assertion);

    }


    @Override
    public int hashCode() {
        return assertion.hashCode();
    }


    /**
     * Parses a SAML 2.0 bearer grant from the specified request body
     * parameters.
     *
     * <p>Example:
     *
     * <pre>
     * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-
     * bearer&amp;assertion=PEFzc2VydGlvbiBJc3N1ZUluc3RhbnQ9IjIwMTEtMDU
     * [...omitted for brevity...]aG5TdGF0ZW1lbnQ-PC9Bc3NlcnRpb24-
     * </pre>
     *
     * @param params The parameters.
     * @return The SAML 2.0 bearer grant.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static SAML2BearerGrant parse(Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        // Parse grant type
        String grantTypeString = MultivaluedMapUtils.getFirstValue(params, "grant_type");

        if (grantTypeString == null) {
            throw MISSING_GRANT_TYPE_PARAM_EXCEPTION;
        }

        if (!GrantType.parse(grantTypeString).equals(GRANT_TYPE)) {
            throw UNSUPPORTED_GRANT_TYPE_EXCEPTION;
        }

        // Parse JWT assertion
        String assertionString = MultivaluedMapUtils.getFirstValue(params, "assertion");

        if (assertionString == null || assertionString.trim().isEmpty()) {
            throw MISSING_ASSERTION_PARAM_EXCEPTION;
        }

        return new SAML2BearerGrant(new Base64URLValue(assertionString));
    }
}
