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


import be.atbash.ee.oauth2.sdk.id.Identifier;

/**
 * Authorisation response mode.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM).
 * </ul>
 */
public final class ResponseMode extends Identifier {


    /**
     * The authorisation response parameters are encoded in the query
     * string added to the {@code redirect_uri} when redirecting back to
     * the client.
     */
    public static final ResponseMode QUERY = new ResponseMode("query");


    /**
     * The authorisation response parameters are encoded in the fragment
     * added to the {@code redirect_uri} when redirecting back to the
     * client.
     */
    public static final ResponseMode FRAGMENT = new ResponseMode("fragment");


    /**
     * The authorisation response parameters are encoded as HTML form
     * values that are auto-submitted in the User Agent, and thus are
     * transmitted via the HTTP POST method to the client, with the result
     * parameters being encoded in the body using the
     * {@code application/x-www-form-urlencoded} format. The action
     * attribute of the form MUST be the client's redirection URI. The
     * method of the form attribute MUST be POST.
     */
    public static final ResponseMode FORM_POST = new ResponseMode("form_post");


    /**
     * The authorisation response parameters are packaged in a JSON Web
     * Token (JWT) which is returned as a {@code response} query parameter
     * added to the {@code redirect_uri} when redirecting back to the
     * client.
     */
    public static final ResponseMode QUERY_JWT = new ResponseMode("query.jwt");


    /**
     * The authorisation response parameters are packaged in a JSON Web
     * Token (JWT) which is returned as a {@code response} fragment
     * parameter added to the {@code redirect_uri} when redirecting back to
     * the client.
     */
    public static final ResponseMode FRAGMENT_JWT = new ResponseMode("fragment.jwt");


    /**
     * The authorisation response parameters are packaged in a JSON Web
     * Token (JWT) which is transmitted via the HTTP POST method to the
     * client. The action attribute of the form MUST be the client's
     * redirection URI. The method of the form attribute MUST be POST.
     */
    public static final ResponseMode FORM_POST_JWT = new ResponseMode("form_post.jwt");


    /**
     * The authorisation response parameters are packaged in a JSON Web
     * Token (JWT) which is returned as a {@code response} parameter using
     * the redirect encoding ({@link #QUERY_JWT query.jwt},
     * {@link #FRAGMENT_JWT fragment.jwt} for the requested
     * {@code response_type}.
     */
    public static final ResponseMode JWT = new ResponseMode("jwt");


    /**
     * Resolves the requested response mode.
     *
     * @param rm The explicitly requested response mode
     *           ({@code response_mode}), {@code null} if not specified.
     * @param rt The response type ({@code response_type}), {@code null} if
     *           not known.
     * @return The resolved response mode.
     */
    public static ResponseMode resolve(final ResponseMode rm, final ResponseType rt) {

        if (rm != null) {
            // Explicitly requested response_mode
            if (ResponseMode.JWT.equals(rm)) {
                // https://openid.net//specs/openid-financial-api-jarm.html#response-mode-jwt
                if (rt != null && (rt.impliesImplicitFlow() || rt.impliesHybridFlow())) {
                    return ResponseMode.FRAGMENT_JWT;
                } else {
                    return ResponseMode.QUERY_JWT;
                }
            }

            return rm;

        } else if (rt != null && (rt.impliesImplicitFlow() || rt.impliesHybridFlow())) {
            return ResponseMode.FRAGMENT;
        } else {
            // assume query in all other cases
            return ResponseMode.QUERY;
        }
    }


    /**
     * Creates a new authorisation response mode with the specified value.
     *
     * @param value The response mode value. Must not be {@code null}.
     */
    public ResponseMode(final String value) {

        super(value);
    }


    @Override
    public boolean equals(final Object object) {

        return object instanceof ResponseMode &&
                this.toString().equals(object.toString());
    }
}
