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


import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;


/**
 * OpenID Connect specific errors.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.2.6.
 * </ul>
 */
public final class OIDCError {


    // Authentication endpoint

    /**
     * The authorisation server requires end-user interaction of some form
     * to proceed. This error may be returned when the {@link Prompt}
     * parameter in the {@link AuthenticationRequest} is set to
     * {@link Prompt.Type#NONE none} to request that the authorisation
     * server should not display any user interfaces to the end-user, but
     * the {@link AuthenticationRequest} cannot be completed without
     * displaying a user interface for end-user interaction.
     */
    public static final ErrorObject INTERACTION_REQUIRED =
            new ErrorObject("interaction_required", "User interaction required", HTTPResponse.SC_FOUND);

    /**
     * The authorisation server requires end-user authentication. This
     * error may be returned when the prompt parameter in the
     * {@link AuthenticationRequest} is set to {@link Prompt.Type#NONE}
     * to request that the authorisation server should not display any user
     * interfaces to the end-user, but the {@link AuthenticationRequest}
     * cannot be completed without displaying a user interface for user
     * authentication.
     */
    public static final ErrorObject LOGIN_REQUIRED =
            new ErrorObject("login_required", "Login required", HTTPResponse.SC_FOUND);


    /**
     * The end-user is required to select a session at the authorisation
     * server. The end-user may be authenticated at the authorisation
     * server with different associated accounts, but the end-user did not
     * select a session. This error may be returned when the prompt
     * parameter in the {@link AuthenticationRequest} is set to
     * {@link Prompt.Type#NONE} to request that the authorisation server
     * should not display any user interfaces to the end-user, but the
     * {@link AuthenticationRequest} cannot be completed without
     * displaying a user interface to prompt for a session to use.
     */
    public static final ErrorObject ACCOUNT_SELECTION_REQUIRED =
            new ErrorObject("account_selection_required", "Session selection required", HTTPResponse.SC_FOUND);


    /**
     * The authorisation server requires end-user consent. This error may
     * be returned when the prompt parameter in the
     * {@link AuthenticationRequest} is set to {@link Prompt.Type#NONE}
     * to request that the authorisation server should not display any
     * user interfaces to the end-user, but the
     * {@link AuthenticationRequest} cannot be completed without
     * displaying a user interface for end-user consent.
     */
    public static final ErrorObject CONSENT_REQUIRED =
            new ErrorObject("consent_required", "Consent required", HTTPResponse.SC_FOUND);


    /**
     * The OpenID provider is unable to authenticate the end-user at the
     * required Authentication Context Class Reference value when
     * requested with an essential {@code acr} claim. This error code may
     * also be used in other appropriate cases.
     */
    public static final ErrorObject UNMET_AUTHENTICATION_REQUIREMENTS =
            new ErrorObject("unmet_authentication_requirements", "Unmet authentication requirements", HTTPResponse.SC_FOUND);


    /**
     * The {@code registration} parameter in the
     * {@link AuthenticationRequest} is not supported. Applies only to
     * self-issued OpenID providers.
     */
    public static final ErrorObject REGISTRATION_NOT_SUPPORTED =
            new ErrorObject("registration_not_supported", "Registration parameter not supported", HTTPResponse.SC_FOUND);


    /**
     * Prevents public instantiation.
     */
    private OIDCError() {
    }
}
