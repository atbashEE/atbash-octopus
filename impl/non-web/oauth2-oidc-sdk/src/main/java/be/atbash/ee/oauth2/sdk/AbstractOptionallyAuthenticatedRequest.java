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


import be.atbash.ee.oauth2.sdk.auth.ClientAuthentication;

import java.net.URI;


/**
 * Abstract request with optional client authentication.
 *
 * <p>Client authentication methods:
 *
 * <ul>
 *     <li>{@link be.atbash.ee.oauth2.sdk.auth.ClientSecretBasic client_secret_basic}
 *     <li>{@link be.atbash.ee.oauth2.sdk.auth.ClientSecretPost client_secret_post}
 *     <li>{@link be.atbash.ee.oauth2.sdk.auth.ClientSecretJWT client_secret_jwt}
 *     <li>{@link be.atbash.ee.oauth2.sdk.auth.PrivateKeyJWT private_key_jwt}
 *     <li>{@link be.atbash.ee.oauth2.sdk.auth.SelfSignedTLSClientAuthentication self_signed_tls_client_auth}
 *     <li>{@link be.atbash.ee.oauth2.sdk.auth.PKITLSClientAuthentication tls_client_auth}
 * </ul>
 */
public abstract class AbstractOptionallyAuthenticatedRequest extends AbstractRequest {


    /**
     * The client authentication, {@code null} if none.
     */
    private final ClientAuthentication clientAuth;


    /**
     * Creates a new abstract request with optional client authentication.
     *
     * @param uri        The URI of the endpoint (HTTP or HTTPS) for which
     *                   the request is intended, {@code null} if not
     *                   specified (if, for example, the
     *                   {@link #toHTTPRequest()} method will not be used).
     * @param clientAuth The client authentication, {@code null} if none.
     */
    public AbstractOptionallyAuthenticatedRequest(final URI uri,
                                                  final ClientAuthentication clientAuth) {

        super(uri);

        this.clientAuth = clientAuth;
    }


    /**
     * Returns the client authentication.
     *
     * @return The client authentication, {@code null} if none.
     */
    public ClientAuthentication getClientAuthentication() {

        return clientAuth;
    }
}
