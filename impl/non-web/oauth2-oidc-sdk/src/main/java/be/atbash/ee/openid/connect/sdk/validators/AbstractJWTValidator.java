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
package be.atbash.ee.openid.connect.sdk.validators;


import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;

/**
 * Abstract JSON Web Token (JWT) validator for ID tokens and logout tokens.
 */
public abstract class AbstractJWTValidator {

    /**
     * The expected token issuer.
     */
    private final Issuer expectedIssuer;


    /**
     * The requesting client.
     */
    private final ClientID clientID;


    /**
     * The JWS key selector.
     */
    private final KeySelector jwsKeySelector;


    /**
     * The JWE key selector.
     */
    private final KeySelector jweKeySelector;


    /**
     * The maximum acceptable clock skew, in seconds.
     */
    private int maxClockSkew;


    /**
     * Creates a new abstract JWT validator.
     *
     * @param expectedIssuer The expected token issuer (OpenID Provider).
     *                       Must not be {@code null}.
     * @param clientID       The client ID. Must not be {@code null}.
     * @param jwsKeySelector The key selector for JWS verification,
     *                       {@code null} if unsecured (plain) tokens are
     *                       expected.
     * @param jweKeySelector The key selector for JWE decryption,
     *                       {@code null} if encrypted tokens are not
     *                       expected.
     */
    public AbstractJWTValidator(Issuer expectedIssuer,
                                ClientID clientID,
                                KeySelector jwsKeySelector,
                                KeySelector jweKeySelector) {

        if (expectedIssuer == null) {
            throw new IllegalArgumentException("The expected token issuer must not be null");
        }
        this.expectedIssuer = expectedIssuer;

        if (clientID == null) {
            throw new IllegalArgumentException("The client ID must not be null");
        }
        this.clientID = clientID;

        maxClockSkew = JwtSupportConfiguration.getInstance().getClockSkewSeconds();

        // Optional
        this.jwsKeySelector = jwsKeySelector;
        this.jweKeySelector = jweKeySelector;
    }


    /**
     * Returns the expected token issuer.
     *
     * @return The token issuer.
     */
    public Issuer getExpectedIssuer() {
        return expectedIssuer;
    }


    /**
     * Returns the client ID (the expected JWT audience).
     *
     * @return The client ID.
     */
    public ClientID getClientID() {
        return clientID;
    }


    /**
     * Returns the configured JWS key selector for signed token
     * verification.
     *
     * @return The JWS key selector, {@code null} if none.
     */
    protected KeySelector getJWSKeySelector() {
        return jwsKeySelector;
    }


    /**
     * Returns the configured JWE key selector for encrypted token
     * decryption.
     *
     * @return The JWE key selector, {@code null}.
     */
    protected KeySelector getJWEKeySelector() {
        return jweKeySelector;
    }


    /**
     * Gets the maximum acceptable clock skew for verifying the token
     * timestamps.
     *
     * @return The maximum acceptable clock skew, in seconds. Zero
     * indicates none.
     */
    protected int getMaxClockSkew() {

        return maxClockSkew;
    }


    /**
     * Sets the maximum acceptable clock skew for verifying the token
     * timestamps.
     *
     * @param maxClockSkew The maximum acceptable clock skew, in seconds.
     *                     Zero indicates none. Must not be negative.
     */
    public void setMaxClockSkew(int maxClockSkew) {

        this.maxClockSkew = maxClockSkew;
    }
}
