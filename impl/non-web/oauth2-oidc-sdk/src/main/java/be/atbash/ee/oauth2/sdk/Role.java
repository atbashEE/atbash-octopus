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
 * Enumeration of the OAuth 2.0 roles.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 1.1.
 * </ul>
 */
public enum Role {


    /**
     * An entity capable of granting access to a protected resource. When
     * the resource owner is a person, it is referred to as an end-user.
     */
    RESOURCE_OWNER,


    /**
     * The server hosting the protected resources, capable of accepting
     * and responding to protected resource requests using access tokens.
     */
    RESOURCE_SERVER,


    /**
     * An application making protected resource requests on behalf of the
     * resource owner and with its authorization.  The term "client" does
     * not imply any particular implementation characteristics (e.g.
     * whether the application executes on a server, a desktop, or other
     * devices).
     */
    CLIENT,


    /**
     * The server issuing access tokens to the client after successfully
     * authenticating the resource owner and obtaining authorization.
     */
    AUTHORIZATION_SERVER
}