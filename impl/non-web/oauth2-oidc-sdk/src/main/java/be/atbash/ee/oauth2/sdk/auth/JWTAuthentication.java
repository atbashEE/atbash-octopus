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
package be.atbash.ee.oauth2.sdk.auth;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.SerializeException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;

import javax.mail.internet.ContentType;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Base abstract class for JSON Web Token (JWT) based client authentication at
 * the Token endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 3.2.1.
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 *     <li>OpenID Connect Core 1.0, section 9.
 * </ul>
 */
public abstract class JWTAuthentication extends ClientAuthentication {


    /**
     * The expected client assertion type, corresponding to the
     * {@code client_assertion_type} parameter. This is a URN string set to
     * "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".
     */
    public static final String CLIENT_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";


    /**
     * The client assertion, corresponding to the {@code client_assertion}
     * parameter. The assertion is in the form of a signed JWT.
     */
    private final SignedJWT clientAssertion;


    /**
     * The JWT authentication claims set for the client assertion.
     */
    private final JWTAuthenticationClaimsSet jwtAuthClaimsSet;


    /**
     * Parses the client identifier from the specified signed JWT that
     * represents a client assertion.
     *
     * @param jwt The signed JWT to parse. Must not be {@code null}.
     * @return The parsed client identifier.
     * @throws IllegalArgumentException If the client identifier couldn't
     *                                  be parsed.
     */
    private static ClientID parseClientID(final SignedJWT jwt) {

        String subjectValue;
        String issuerValue;

        try {
            subjectValue = jwt.getJWTClaimsSet().getSubject();
            issuerValue = jwt.getJWTClaimsSet().getIssuer();

        } catch (java.text.ParseException e) {

            throw new IllegalArgumentException(e.getMessage(), e);
        }

        if (subjectValue == null) {
            throw new IllegalArgumentException("Missing subject in client JWT assertion");
        }

        if (issuerValue == null) {
            throw new IllegalArgumentException("Missing issuer in client JWT assertion");
        }

        if (!subjectValue.equals(issuerValue)) {
            throw new IllegalArgumentException("Issuer and subject in client JWT assertion must designate the same client identifier");
        }

        return new ClientID(subjectValue);
    }


    /**
     * Creates a new JSON Web Token (JWT) based client authentication.
     *
     * @param method          The client authentication method. Must not be
     *                        {@code null}.
     * @param clientAssertion The client assertion, corresponding to the
     *                        {@code client_assertion} parameter, in the
     *                        form of a signed JSON Web Token (JWT). Must
     *                        be signed and not {@code null}.
     * @throws IllegalArgumentException If the client assertion is not
     *                                  signed or doesn't conform to the
     *                                  expected format.
     */
    protected JWTAuthentication(final ClientAuthenticationMethod method,
                                final SignedJWT clientAssertion) {

        super(method, parseClientID(clientAssertion));

        if (!clientAssertion.getState().equals(JWSObject.State.SIGNED)) {
            throw new IllegalArgumentException("The client assertion JWT must be signed");
        }

        this.clientAssertion = clientAssertion;

        try {
            jwtAuthClaimsSet = JWTAuthenticationClaimsSet.parse(clientAssertion.getJWTClaimsSet());

        } catch (Exception e) {

            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }


    /**
     * Gets the client assertion, corresponding to the
     * {@code client_assertion} parameter.
     *
     * @return The client assertion, in the form of a signed JSON Web Token
     * (JWT).
     */
    public SignedJWT getClientAssertion() {

        return clientAssertion;
    }


    /**
     * Gets the client authentication claims set contained in the client
     * assertion JSON Web Token (JWT).
     *
     * @return The client authentication claims.
     */
    public JWTAuthenticationClaimsSet getJWTAuthenticationClaimsSet() {

        return jwtAuthClaimsSet;
    }


    /**
     * Returns the parameter representation of this JSON Web Token (JWT)
     * based client authentication. Note that the parameters are not
     * {@code application/x-www-form-urlencoded} encoded.
     *
     * <p>Parameters map:
     *
     * <pre>
     * "client_assertion" = [serialised-JWT]
     * "client_assertion_type" = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
     * </pre>
     *
     * @return The parameters map, with keys "client_assertion",
     * "client_assertion_type" and "client_id".
     */
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = new HashMap<>();

        try {
            params.put("client_assertion", Collections.singletonList(clientAssertion.serialize()));

        } catch (IllegalStateException e) {

            throw new SerializeException("Couldn't serialize JWT to a client assertion string: " + e.getMessage(), e);
        }

        params.put("client_assertion_type", Collections.singletonList(CLIENT_ASSERTION_TYPE));

        return params;
    }


    @Override
    public void applyTo(final HTTPRequest httpRequest) {

        if (httpRequest.getMethod() != HTTPRequest.Method.POST) {
            throw new SerializeException("The HTTP request method must be POST");
        }

        ContentType ct = httpRequest.getContentType();

        if (ct == null) {
            throw new SerializeException("Missing HTTP Content-Type header");
        }

        if (!ct.match(CommonContentTypes.APPLICATION_URLENCODED)) {
            throw new SerializeException("The HTTP Content-Type header must be " + CommonContentTypes.APPLICATION_URLENCODED);
        }

        Map<String, List<String>> params = httpRequest.getQueryParameters();

        params.putAll(toParameters());

        String queryString = URLUtils.serializeParameters(params);

        httpRequest.setQuery(queryString);
    }


    /**
     * Ensures the specified parameters map contains an entry with key
     * "client_assertion_type" pointing to a string that equals the expected
     * {@link #CLIENT_ASSERTION_TYPE}. This method is intended to aid
     * parsing of JSON Web Token (JWT) based client authentication objects.
     *
     * @param params The parameters map to check. The parameters must not be
     *               {@code null} and
     *               {@code application/x-www-form-urlencoded} encoded.
     * @throws OAuth2JSONParseException If expected "client_assertion_type" entry
     *                                  wasn't found.
     */
    protected static void ensureClientAssertionType(final Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        final String clientAssertionType = MultivaluedMapUtils.getFirstValue(params, "client_assertion_type");

        if (clientAssertionType == null) {
            throw new OAuth2JSONParseException("Missing \"client_assertion_type\" parameter");
        }

        if (!clientAssertionType.equals(CLIENT_ASSERTION_TYPE)) {
            throw new OAuth2JSONParseException("Invalid \"client_assertion_type\" parameter, must be " + CLIENT_ASSERTION_TYPE);
        }
    }


    /**
     * Parses the specified parameters map for a client assertion. This
     * method is intended to aid parsing of JSON Web Token (JWT) based
     * client authentication objects.
     *
     * @param params The parameters map to parse. It must contain an entry
     *               with key "client_assertion" pointing to a string that
     *               represents a signed serialised JSON Web Token (JWT).
     *               The parameters must not be {@code null} and
     *               {@code application/x-www-form-urlencoded} encoded.
     * @return The client assertion as a signed JSON Web Token (JWT).
     * @throws OAuth2JSONParseException If a "client_assertion" entry couldn't be
     *                                  retrieved from the parameters map.
     */
    protected static SignedJWT parseClientAssertion(final Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        final String clientAssertion = MultivaluedMapUtils.getFirstValue(params, "client_assertion");

        if (clientAssertion == null) {
            throw new OAuth2JSONParseException("Missing \"client_assertion\" parameter");
        }

        try {
            return SignedJWT.parse(clientAssertion);

        } catch (java.text.ParseException e) {

            throw new OAuth2JSONParseException("Invalid \"client_assertion\" JWT: " + e.getMessage(), e);
        }
    }

    /**
     * Parses the specified parameters map for an optional client
     * identifier. This method is intended to aid parsing of JSON Web Token
     * (JWT) based client authentication objects.
     *
     * @param params The parameters map to parse. It may contain an entry
     *               with key "client_id" pointing to a string that
     *               represents the client identifier. The parameters must
     *               not be {@code null} and
     *               {@code application/x-www-form-urlencoded} encoded.
     * @return The client identifier, {@code null} if not specified.
     */
    protected static ClientID parseClientID(final Map<String, List<String>> params) {

        String clientIDString = MultivaluedMapUtils.getFirstValue(params, "client_id");

        if (clientIDString == null) {
            return null;
        } else {
            return new ClientID(clientIDString);
        }
    }


    /**
     * Parses the specified HTTP request for a JSON Web Token (JWT) based
     * client authentication.
     *
     * @param httpRequest The HTTP request to parse. Must not be {@code null}.
     * @return The JSON Web Token (JWT) based client authentication.
     * @throws OAuth2JSONParseException If a JSON Web Token (JWT) based client
     *                                  authentication couldn't be retrieved from the
     *                                  HTTP request.
     */
    public static JWTAuthentication parse(final HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        httpRequest.ensureMethod(HTTPRequest.Method.POST);
        httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);

        String query = httpRequest.getQuery();

        if (query == null) {
            throw new OAuth2JSONParseException("Missing HTTP POST request entity body");
        }

        Map<String, List<String>> params = URLUtils.parseParameters(query);

        JWSAlgorithm alg = parseClientAssertion(params).getHeader().getAlgorithm();

        if (ClientSecretJWT.supportedJWAs().contains(alg)) {
            return ClientSecretJWT.parse(params);
        } else if (PrivateKeyJWT.supportedJWAs().contains(alg)) {
            return PrivateKeyJWT.parse(params);
        } else {
            throw new OAuth2JSONParseException("Unsupported signed JWT algorithm: " + alg);
        }
    }
}
