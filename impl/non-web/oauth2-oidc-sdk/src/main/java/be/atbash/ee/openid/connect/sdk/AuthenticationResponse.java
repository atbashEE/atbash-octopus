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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.Response;
import be.atbash.ee.oauth2.sdk.id.State;

import java.net.URI;


/**
 * OpenID Connect authentication response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 3.1.2.5. and 3.1.2.6.
 * </ul>
 */
public interface AuthenticationResponse extends Response {


    /**
     * Gets the base redirection URI.
     *
     * @return The base redirection URI (without the appended error
     * response parameters).
     */
    URI getRedirectionURI();


    /**
     * Gets the optional state.
     *
     * @return The state, {@code null} if not requested.
     */
    State getState();


    /**
     * Casts this response to an authentication success response.
     *
     * @return The authentication success response.
     */
    AuthenticationSuccessResponse toSuccessResponse();


    /**
     * Casts this response to an authentication error response.
     *
     * @return The authentication error response.
     */
    AuthenticationErrorResponse toErrorResponse();
}
