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


import be.atbash.ee.oauth2.sdk.id.ClientID;


/**
 * Base abstract class for plain secret based client authentication at the
 * Token endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 2.3.1 and 3.2.1.
 *     <li>OpenID Connect Core 1.0, section 9.
 * </ul>
 */
public abstract class PlainClientSecret extends ClientAuthentication {


    /**
     * The client secret.
     */
    private final Secret secret;


    /**
     * Creates a new plain secret based client authentication.
     *
     * @param method   The client authentication method. Must not be
     *                 {@code null}.
     * @param clientID The client identifier. Must not be {@code null}.
     * @param secret   The client secret. Must not be {@code null}.
     */
    protected PlainClientSecret(final ClientAuthenticationMethod method,
                                final ClientID clientID,
                                final Secret secret) {

        super(method, clientID);

        if (secret == null) {
            throw new IllegalArgumentException("The client secret must not be null");
        }

        this.secret = secret;
    }


    /**
     * Gets the client secret.
     *
     * @return The client secret.
     */
    public Secret getClientSecret() {

        return secret;
    }
}
