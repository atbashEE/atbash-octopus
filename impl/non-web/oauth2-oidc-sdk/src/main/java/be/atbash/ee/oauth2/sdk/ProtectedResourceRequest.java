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


import be.atbash.ee.oauth2.sdk.token.AccessToken;

import java.net.URI;


/**
 * Base abstract class for protected resource requests using an OAuth 2.0
 * access token.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>RFC 6749
 * </ul>
 */
public abstract class ProtectedResourceRequest extends AbstractRequest {


    /**
     * OAuth 2.0 Bearer access token.
     */
    private final AccessToken accessToken;


    /**
     * Creates a new protected resource request.
     *
     * @param uri         The URI of the protected resource. May be
     *                    {@code null} if the {@link #toHTTPRequest()}
     *                    method will not be used.
     * @param accessToken An OAuth 2.0 access token for the request,
     *                    {@code null} if none.
     */
    protected ProtectedResourceRequest(final URI uri, final AccessToken accessToken) {

        super(uri);

        this.accessToken = accessToken;
    }


    /**
     * Gets the OAuth 2.0 access token for this protected resource request.
     *
     * @return The OAuth 2.0 access token, {@code null} if none.
     */
    public AccessToken getAccessToken() {

        return accessToken;
    }
}