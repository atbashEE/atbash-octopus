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
package be.atbash.ee.oauth2.sdk.auth.verifier;


import be.atbash.ee.oauth2.sdk.BadJWTException;
import be.atbash.ee.oauth2.sdk.auth.*;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.util.CollectionUtils;
import be.atbash.ee.oauth2.sdk.util.X509CertificateUtils;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.factories.DefaultJWSVerifierFactory;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWSVerifierFactory;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSVerifier;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;


/**
 * Client authentication verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 2.3.1 and 3.2.1.
 *     <li>OpenID Connect Core 1.0, section 9.
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (draft-ietf-oauth-mtls-15), section 2.
 * </ul>
 */
public class ClientAuthenticationVerifier<T> {


    /**
     * The client credentials selector.
     */
    private final ClientCredentialsSelector<T> clientCredentialsSelector;


    /**
     * Optional client X.509 certificate binding verifier for
     * {@code tls_client_auth}.
     */
    private final PKIClientX509CertificateBindingVerifier<T> pkiCertBindingVerifier;


    /**
     * The JWT assertion claims set verifier.
     */
    private final JWTAuthenticationClaimsSetVerifier claimsSetVerifier;


    /**
     * JWS verifier factory for private_key_jwt authentication.
     */
    private final JWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();


    /**
     * Creates a new client authentication verifier.
     *
     * @param clientCredentialsSelector The client credentials selector.
     *                                  Must not be {@code null}.
     * @param pkiCertBindingVerifier    Optional client X.509 certificate
     *                                  binding verifier for
     *                                  {@code tls_client_auth},
     *                                  {@code null} if not supported.
     * @param expectedAudience          The permitted audience (aud) claim
     *                                  values in JWT authentication
     *                                  assertions. Must not be empty or
     *                                  {@code null}. Should typically
     *                                  contain the token endpoint URI and
     *                                  for OpenID provider it may also
     *                                  include the issuer URI.
     */
    public ClientAuthenticationVerifier(ClientCredentialsSelector<T> clientCredentialsSelector,
                                        PKIClientX509CertificateBindingVerifier<T> pkiCertBindingVerifier,
                                        Set<Audience> expectedAudience) {

        claimsSetVerifier = new JWTAuthenticationClaimsSetVerifier(expectedAudience);

        if (clientCredentialsSelector == null) {
            throw new IllegalArgumentException("The client credentials selector must not be null");
        }

        this.pkiCertBindingVerifier = pkiCertBindingVerifier;

        this.clientCredentialsSelector = clientCredentialsSelector;
    }


    /**
     * Returns the client credentials selector.
     *
     * @return The client credentials selector.
     */
    public ClientCredentialsSelector<T> getClientCredentialsSelector() {

        return clientCredentialsSelector;
    }


    /**
     * Returns the client X.509 certificate binding verifier for use in
     * {@code tls_client_auth}.
     *
     * @return The client X.509 certificate binding verifier, {@code null}
     * if not specified.
     */
    public PKIClientX509CertificateBindingVerifier<T> getPKIClientX509CertificateBindingVerifier() {

        return pkiCertBindingVerifier;
    }


    /**
     * Returns the permitted audience values in JWT authentication
     * assertions.
     *
     * @return The permitted audience (aud) claim values.
     */
    public Set<Audience> getExpectedAudience() {

        return claimsSetVerifier.getExpectedAudience();
    }


    /**
     * Verifies a client authentication request.
     *
     * @param clientAuth The client authentication. Must not be
     *                   {@code null}.
     * @param hints      Optional hints to the verifier, empty set of
     *                   {@code null} if none.
     * @param context    Additional context to be passed to the client
     *                   credentials selector. May be {@code null}.
     * @throws InvalidClientException If the client authentication is
     *                                invalid, typically due to bad
     *                                credentials.
     * @throws JOSEException          If authentication failed due to an
     *                                internal JOSE / JWT processing
     *                                exception.
     */
    public void verify(ClientAuthentication clientAuth, Set<Hint> hints, Context<T> context)
            throws InvalidClientException, JOSEException {

        if (clientAuth instanceof PlainClientSecret) {

            List<Secret> secretCandidates = clientCredentialsSelector.selectClientSecrets(
                    clientAuth.getClientID(),
                    clientAuth.getMethod(),
                    context);

            if (CollectionUtils.isEmpty(secretCandidates)) {
                throw InvalidClientException.NO_REGISTERED_SECRET;
            }

            PlainClientSecret plainAuth = (PlainClientSecret) clientAuth;

            for (Secret candidate : secretCandidates) {
                // constant time, SHA-256 based
                if (plainAuth.getClientSecret().equalsSHA256Based(candidate)) {
                    return; // success
                }
            }

            throw InvalidClientException.BAD_SECRET;

        } else if (clientAuth instanceof ClientSecretJWT) {

            ClientSecretJWT jwtAuth = (ClientSecretJWT) clientAuth;

            // Check claims first before requesting secret from backend
            try {
                claimsSetVerifier.verify(jwtAuth.getJWTAuthenticationClaimsSet().toJWTClaimsSet());
            } catch (BadJWTException e) {
                throw new InvalidClientException("Bad / expired JWT claims: " + e.getMessage());
            }

            List<Secret> secretCandidates = clientCredentialsSelector.selectClientSecrets(
                    clientAuth.getClientID(),
                    clientAuth.getMethod(),
                    context);

            if (CollectionUtils.isEmpty(secretCandidates)) {
                throw InvalidClientException.NO_REGISTERED_SECRET;
            }

            SignedJWT assertion = jwtAuth.getClientAssertion();

            for (Secret candidate : secretCandidates) {

                boolean valid = assertion.verify(new MACVerifier(candidate.getValueBytes()));

                if (valid) {
                    return; // success
                }
            }

            throw InvalidClientException.BAD_JWT_HMAC;

        } else if (clientAuth instanceof PrivateKeyJWT) {

            PrivateKeyJWT jwtAuth = (PrivateKeyJWT) clientAuth;

            // Check claims first before requesting / retrieving public keys
            try {
                claimsSetVerifier.verify(jwtAuth.getJWTAuthenticationClaimsSet().toJWTClaimsSet());
            } catch (BadJWTException e) {
                throw new InvalidClientException("Bad / expired JWT claims: " + e.getMessage());
            }

            List<? extends PublicKey> keyCandidates = clientCredentialsSelector.selectPublicKeys(
                    jwtAuth.getClientID(),
                    jwtAuth.getMethod(),
                    jwtAuth.getClientAssertion().getHeader(),
                    false,        // don't force refresh if we have a remote JWK set;
                    // selector may however do so if it encounters an unknown key ID
                    context);

            if (CollectionUtils.isEmpty(keyCandidates)) {
                throw InvalidClientException.NO_MATCHING_JWK;
            }

            SignedJWT assertion = jwtAuth.getClientAssertion();

            for (PublicKey candidate : keyCandidates) {

                if (candidate == null) {
                    continue; // skip
                }

                JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(
                        jwtAuth.getClientAssertion().getHeader(),
                        candidate);

                boolean valid = assertion.verify(jwsVerifier);

                if (valid) {
                    return; // success
                }
            }

            // Second pass
            if (hints != null && hints.contains(Hint.CLIENT_HAS_REMOTE_JWK_SET)) {
                // Client possibly registered JWK set URL with keys that have no IDs
                // force JWK set reload from URL and retry
                keyCandidates = clientCredentialsSelector.selectPublicKeys(
                        jwtAuth.getClientID(),
                        jwtAuth.getMethod(),
                        jwtAuth.getClientAssertion().getHeader(),
                        true, // force reload of remote JWK set
                        context);

                if (CollectionUtils.isEmpty(keyCandidates)) {
                    throw InvalidClientException.NO_MATCHING_JWK;
                }

                assertion = jwtAuth.getClientAssertion();

                for (PublicKey candidate : keyCandidates) {

                    if (candidate == null) {
                        continue; // skip
                    }

                    JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(
                            jwtAuth.getClientAssertion().getHeader(),
                            candidate);

                    boolean valid = assertion.verify(jwsVerifier);

                    if (valid) {
                        return; // success
                    }
                }
            }

            throw InvalidClientException.BAD_JWT_SIGNATURE;

        } else if (clientAuth instanceof SelfSignedTLSClientAuthentication) {

            SelfSignedTLSClientAuthentication tlsClientAuth = (SelfSignedTLSClientAuthentication) clientAuth;

            X509Certificate clientCert = tlsClientAuth.getClientX509Certificate();

            if (clientCert == null) {
                // Sanity check
                throw new InvalidClientException("Missing client X.509 certificate");
            }

            // Self-signed certs bound to registered public key in client jwks / jwks_uri
            List<? extends PublicKey> keyCandidates = clientCredentialsSelector.selectPublicKeys(
                    tlsClientAuth.getClientID(),
                    tlsClientAuth.getMethod(),
                    null,
                    false, // don't force refresh if we have a remote JWK set;
                    // selector may however do so if it encounters an unknown key ID
                    context);

            if (CollectionUtils.isEmpty(keyCandidates)) {
                throw InvalidClientException.NO_MATCHING_JWK;
            }

            for (PublicKey candidate : keyCandidates) {

                if (candidate == null) {
                    continue; // skip
                }

                boolean valid = X509CertificateUtils.publicKeyMatches(clientCert, candidate);

                if (valid) {
                    return; // success
                }
            }

            // Second pass
            if (hints != null && hints.contains(Hint.CLIENT_HAS_REMOTE_JWK_SET)) {
                // Client possibly registered JWK set URL with keys that have no IDs
                // force JWK set reload from URL and retry
                keyCandidates = clientCredentialsSelector.selectPublicKeys(
                        tlsClientAuth.getClientID(),
                        tlsClientAuth.getMethod(),
                        null,
                        true, // force reload of remote JWK set
                        context);

                if (CollectionUtils.isEmpty(keyCandidates)) {
                    throw InvalidClientException.NO_MATCHING_JWK;
                }

                for (PublicKey candidate : keyCandidates) {

                    if (candidate == null) {
                        continue; // skip
                    }

                    boolean valid = X509CertificateUtils.publicKeyMatches(clientCert, candidate);

                    if (valid) {
                        return; // success
                    }
                }
            }

            throw InvalidClientException.BAD_SELF_SIGNED_CLIENT_CERTIFICATE;

        } else if (clientAuth instanceof PKITLSClientAuthentication) {

            PKITLSClientAuthentication tlsClientAuth = (PKITLSClientAuthentication) clientAuth;
            if (pkiCertBindingVerifier != null) {
                pkiCertBindingVerifier.verifyCertificateBinding(
                        clientAuth.getClientID(),
                        tlsClientAuth.getClientX509Certificate(),
                        context);

            } else {
                throw new InvalidClientException("Mutual TLS client Authentication (tls_client_auth) not supported");
            }
        } else {
            throw new RuntimeException("Unexpected client authentication: " + clientAuth.getMethod());
        }
    }
}
