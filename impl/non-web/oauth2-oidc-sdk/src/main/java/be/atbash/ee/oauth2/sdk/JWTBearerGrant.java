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
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObject;
import be.atbash.ee.security.octopus.nimbus.jose.PlainObject;
import be.atbash.ee.security.octopus.nimbus.jwt.EncryptedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * JWT bearer grant. Used in access token requests with a JSON Web Token (JWT),
 * such an OpenID Connect ID token.
 *
 * <p>The JWT assertion can be:
 *
 * <ul>
 *     <li>Signed or MAC protected with JWS
 *     <li>Encrypted with JWE
 *     <li>Nested - signed / MAC protected with JWS and then encrypted with JWE
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521), section 4.1.
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523), section-2.1.
 * </ul>
 */
public class JWTBearerGrant extends AssertionGrant {


    /**
     * The grant type.
     */
    public static final GrantType GRANT_TYPE = GrantType.JWT_BEARER;


    private static final String UNSUPPORTED_GRANT_TYPE_MESSAGE = "The \"grant_type\" must be " + GRANT_TYPE;


    private static final String PLAIN_ASSERTION_REJECTED_MESSAGE = "The JWT assertion must not be unsecured (plain)";


    private static final String JWT_PARSE_MESSAGE = "The \"assertion\" is not a JWT";


    /**
     * Cached {@code unsupported_grant_type} exception.
     */
    private static final OAuth2JSONParseException UNSUPPORTED_GRANT_TYPE_EXCEPTION
            = new OAuth2JSONParseException(UNSUPPORTED_GRANT_TYPE_MESSAGE,
            OAuth2Error.UNSUPPORTED_GRANT_TYPE.appendDescription(": " + UNSUPPORTED_GRANT_TYPE_MESSAGE));


    /**
     * Cached plain JOSE / JWT rejected exception.
     */
    private static final OAuth2JSONParseException PLAIN_ASSERTION_REJECTED_EXCEPTION
            = new OAuth2JSONParseException(PLAIN_ASSERTION_REJECTED_MESSAGE,
            OAuth2Error.INVALID_REQUEST.appendDescription(": " + PLAIN_ASSERTION_REJECTED_MESSAGE));


    /**
     * Cached JWT assertion parse exception.
     */
    private static final OAuth2JSONParseException JWT_PARSE_EXCEPTION
            = new OAuth2JSONParseException(JWT_PARSE_MESSAGE,
            OAuth2Error.INVALID_REQUEST.appendDescription(": " + JWT_PARSE_MESSAGE));

    /**
     * The assertion - signed JWT, encrypted JWT or nested signed+encrypted
     * JWT.
     */
    private final JOSEObject assertion;


    /**
     * Creates a new signed JSON Web Token (JWT) bearer assertion grant.
     *
     * @param assertion The signed JSON Web Token (JWT) assertion. Must not
     *                  be in a unsigned state or {@code null}. The JWT
     *                  claims are not validated for compliance with the
     *                  standard.
     */
    public JWTBearerGrant(final SignedJWT assertion) {

        super(GRANT_TYPE);

        if (assertion.getState().equals(JWSObject.State.UNSIGNED)) {
            throw new IllegalArgumentException("The JWT assertion must not be in a unsigned state");
        }

        this.assertion = assertion;
    }


    /**
     * Creates a new nested signed and encrypted JSON Web Token (JWT)
     * bearer assertion grant.
     *
     * @param assertion The nested signed and encrypted JSON Web Token
     *                  (JWT) assertion. Must not be in a unencrypted state
     *                  or {@code null}. The JWT claims are not validated
     *                  for compliance with the standard.
     */
    public JWTBearerGrant(final JWEObject assertion) {

        super(GRANT_TYPE);

        if (assertion.getState().equals(JWEObject.State.UNENCRYPTED)) {
            throw new IllegalArgumentException("The JWT assertion must not be in a unencrypted state");
        }

        this.assertion = assertion;
    }


    /**
     * Creates a new signed and encrypted JSON Web Token (JWT) bearer
     * assertion grant.
     *
     * @param assertion The signed and encrypted JSON Web Token (JWT)
     *                  assertion. Must not be in a unencrypted state or
     *                  {@code null}. The JWT claims are not validated for
     *                  compliance with the standard.
     */
    public JWTBearerGrant(final EncryptedJWT assertion) {

        this((JWEObject) assertion);
    }


    /**
     * Gets the JSON Web Token (JWT) bearer assertion.
     *
     * @return The assertion as a signed or encrypted JWT, {@code null} if
     * the assertion is a signed and encrypted JWT.
     */
    public JWT getJWTAssertion() {

        return assertion instanceof JWT ? (JWT) assertion : null;
    }


    /**
     * Gets the JSON Web Token (JWT) bearer assertion.
     *
     * @return The assertion as a generic JOSE object (signed JWT,
     * encrypted JWT, or signed and encrypted JWT).
     */
    public JOSEObject getJOSEAssertion() {

        return assertion;
    }


    @Override
    public String getAssertion() {

        return assertion.serialize();
    }


    @Override
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = new LinkedHashMap<>();
        params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
        params.put("assertion", Collections.singletonList(assertion.serialize()));
        return params;
    }


    /**
     * Parses a JWT bearer grant from the specified request body
     * parameters. The JWT claims are not validated for compliance with the
     * standard.
     *
     * <p>Example:
     *
     * <pre>
     * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
     * &amp;assertion=eyJhbGciOiJFUzI1NiJ9.eyJpc3Mi[...omitted for brevity...].
     * J9l-ZhwP[...omitted for brevity...]
     * </pre>
     *
     * @param params The parameters.
     * @return The JWT bearer grant.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static JWTBearerGrant parse(final Map<String, List<String>> params)
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

        try {
            final JOSEObject assertion = JOSEObject.parse(assertionString);

            if (assertion instanceof PlainObject) {

                throw PLAIN_ASSERTION_REJECTED_EXCEPTION;

            } else if (assertion instanceof JWSObject) {

                return new JWTBearerGrant(new SignedJWT(
                        assertion.getParsedParts()[0],
                        assertion.getParsedParts()[1],
                        assertion.getParsedParts()[2]));

            } else {
                // JWE

                if ("JWT".equalsIgnoreCase(assertion.getHeader().getContentType())) {
                    // Assume nested: signed JWT inside JWE
                    // http://tools.ietf.org/html/rfc7519#section-5.2
                    return new JWTBearerGrant((JWEObject) assertion);
                } else {
                    // Assume encrypted JWT
                    return new JWTBearerGrant(new EncryptedJWT(
                            assertion.getParsedParts()[0],
                            assertion.getParsedParts()[1],
                            assertion.getParsedParts()[2],
                            assertion.getParsedParts()[3],
                            assertion.getParsedParts()[4]));
                }
            }

        } catch (java.text.ParseException e) {
            throw JWT_PARSE_EXCEPTION;
        }
    }
}
