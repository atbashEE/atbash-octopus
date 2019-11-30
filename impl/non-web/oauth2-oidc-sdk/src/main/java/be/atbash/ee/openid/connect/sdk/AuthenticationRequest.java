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


import be.atbash.ee.oauth2.sdk.*;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.pkce.CodeChallenge;
import be.atbash.ee.oauth2.sdk.pkce.CodeChallengeMethod;
import be.atbash.ee.oauth2.sdk.pkce.CodeVerifier;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URIUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.openid.connect.sdk.claims.ACR;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.util.StringUtils;

import javax.json.JsonObject;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.*;


/**
 * OpenID Connect authentication request. Intended to authenticate an end-user
 * and request the end-user's authorisation to release information to the
 * client. Supports custom request parameters.
 *
 * <p>Example HTTP request (code flow):
 *
 * <pre>
 * https://server.example.com/op/authorize?
 * response_type=code%20id_token
 * &amp;client_id=s6BhdRkqt3
 * &amp;redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
 * &amp;scope=openid
 * &amp;nonce=n-0S6_WzA2Mj
 * &amp;state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.2.1.
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636).
 *     <li>Resource Indicators for OAuth 2.0
 *         (draft-ietf-oauth-resource-indicators-00)
 *     <li>The OAuth 2.0 Authorization Framework: JWT Secured Authorization
 *         Request (JAR) draft-ietf-oauth-jwsreq-17
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 * </ul>
 */
public class AuthenticationRequest extends AuthorizationRequest {


    /**
     * The registered parameter names.
     */
    private static final Set<String> REGISTERED_PARAMETER_NAMES;


    static {

        Set<String> p = new HashSet<>(AuthorizationRequest.getRegisteredParameterNames());

        p.add("nonce");
        p.add("display");
        p.add("max_age");
        p.add("ui_locales");
        p.add("claims_locales");
        p.add("id_token_hint");
        p.add("login_hint");
        p.add("acr_values");
        p.add("claims");

        REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
    }


    /**
     * The nonce (required for implicit flow (unless in JAR), optional for
     * code flow).
     */
    private final Nonce nonce;


    /**
     * The requested display type (optional).
     */
    private final Display display;


    /**
     * The required maximum authentication age, in seconds, -1 if not
     * specified, zero implies prompt=login (optional).
     */
    private final int maxAge;


    /**
     * Previously issued ID Token passed to the authorisation server as a
     * hint about the end-user's current or past authenticated session with
     * the client (optional). Should be present when {@code prompt=none} is
     * used.
     */
    private final JWT idTokenHint;


    /**
     * Hint to the authorisation server about the login identifier the
     * end-user may use to log in (optional).
     */
    private final String loginHint;


    /**
     * Requested Authentication Context Class Reference values (optional).
     */
    private final List<ACR> acrValues;


    /**
     * Individual claims to be returned (optional).
     */
    private final ClaimsRequest claims;


    /**
     * Builder for constructing OpenID Connect authentication requests.
     */
    public static class Builder {


        /**
         * The endpoint URI (optional).
         */
        private URI uri;


        /**
         * The response type (required unless in JAR).
         */
        private ResponseType rt;


        /**
         * The client identifier (required unless in JAR).
         */
        private ClientID clientID;


        /**
         * The redirection URI where the response will be sent
         * (required unless in JAR).
         */
        private URI redirectURI;


        /**
         * The scope (required unless in JAR).
         */
        private Scope scope;


        /**
         * The opaque value to maintain state between the request and
         * the callback (recommended).
         */
        private State state;


        /**
         * The nonce (required for implicit flow (unless in JAR),
         * optional for code flow).
         */
        private Nonce nonce;


        /**
         * The requested display type (optional).
         */
        private Display display;


        /**
         * The requested prompt (optional).
         */
        private Prompt prompt;


        /**
         * The required maximum authentication age, in seconds, -1 if
         * not specified, zero implies prompt=login (optional).
         */
        private int maxAge = -1;

        /**
         * Previously issued ID Token passed to the authorisation
         * server as a hint about the end-user's current or past
         * authenticated session with the client (optional). Should be
         * present when {@code prompt=none} is used.
         */
        private JWT idTokenHint;


        /**
         * Hint to the authorisation server about the login identifier
         * the end-user may use to log in (optional).
         */
        private String loginHint;


        /**
         * Requested Authentication Context Class Reference values
         * (optional).
         */
        private List<ACR> acrValues;


        /**
         * Individual claims to be returned (optional).
         */
        private ClaimsRequest claims;


        /**
         * Request object (optional).
         */
        private JWT requestObject;


        /**
         * Request object URI (optional).
         */
        private URI requestURI;


        /**
         * The response mode (optional).
         */
        private ResponseMode rm;


        /**
         * The authorisation code challenge for PKCE (optional).
         */
        private CodeChallenge codeChallenge;


        /**
         * The authorisation code challenge method for PKCE (optional).
         */
        private CodeChallengeMethod codeChallengeMethod;


        /**
         * The resource URI(s) (optional).
         */
        private List<URI> resources;


        /**
         * Indicates incremental authorisation (optional).
         */
        private boolean includeGrantedScopes;


        /**
         * Custom parameters.
         */
        private final Map<String, List<String>> customParams = new HashMap<>();


        /**
         * Creates a new OpenID Connect authentication request builder.
         *
         * @param rt          The response type. Corresponds to the
         *                    {@code response_type} parameter. Must
         *                    specify a valid OpenID Connect response
         *                    type. Must not be {@code null}.
         * @param scope       The request scope. Corresponds to the
         *                    {@code scope} parameter. Must contain an
         *                    {@link OIDCScopeValue#OPENID openid
         *                    value}. Must not be {@code null}.
         * @param clientID    The client identifier. Corresponds to the
         *                    {@code client_id} parameter. Must not be
         *                    {@code null}.
         * @param redirectURI The redirection URI. Corresponds to the
         *                    {@code redirect_uri} parameter. Must not
         *                    be {@code null} unless set by means of
         *                    the optional {@code request_object} /
         *                    {@code request_uri} parameter.
         */
        public Builder(ResponseType rt,
                       Scope scope,
                       ClientID clientID,
                       URI redirectURI) {

            if (rt == null) {
                throw new IllegalArgumentException("The response type must not be null");
            }

            OIDCResponseTypeValidator.validate(rt);

            this.rt = rt;

            if (scope == null) {
                throw new IllegalArgumentException("The scope must not be null");
            }

            if (!scope.contains(OIDCScopeValue.OPENID)) {
                throw new IllegalArgumentException("The scope must include an \"openid\" value");
            }

            this.scope = scope;

            if (clientID == null) {
                throw new IllegalArgumentException("The client ID must not be null");
            }

            this.clientID = clientID;

            // Check presence at build time
            this.redirectURI = redirectURI;
        }


        /**
         * Creates a new JWT secured OpenID Connect authentication
         * request builder.
         *
         * @param requestObject The request object. Must not be
         *                      {@code null}.
         */
        public Builder(JWT requestObject) {

            if (requestObject == null) {
                throw new IllegalArgumentException("The request object must not be null");
            }

            this.requestObject = requestObject;
        }


        /**
         * Creates a new JWT secured OpenID Connect authentication
         * request builder.
         *
         * @param requestURI The request object URI. Must not be
         *                   {@code null}.
         */
        public Builder(URI requestURI) {

            if (requestURI == null) {
                throw new IllegalArgumentException("The request URI must not be null");
            }

            this.requestURI = requestURI;
        }


        /**
         * Creates a new OpenID Connect authentication request builder
         * from the specified request.
         *
         * @param request The OpenID Connect authentication request.
         *                Must not be {@code null}.
         */
        public Builder(AuthenticationRequest request) {

            uri = request.getEndpointURI();
            rt = request.getResponseType();
            clientID = request.getClientID();
            redirectURI = request.getRedirectionURI();
            scope = request.getScope();
            state = request.getState();
            nonce = request.getNonce();
            display = request.getDisplay();
            prompt = request.getPrompt();
            maxAge = request.getMaxAge();
            idTokenHint = request.getIDTokenHint();
            loginHint = request.getLoginHint();
            acrValues = request.getACRValues();
            claims = request.getClaims();
            requestObject = request.getRequestObject();
            requestURI = request.getRequestURI();
            rm = request.getResponseMode();
            codeChallenge = request.getCodeChallenge();
            codeChallengeMethod = request.getCodeChallengeMethod();
            resources = request.getResources();
            includeGrantedScopes = request.includeGrantedScopes();
            customParams.putAll(request.getCustomParameters());
        }


        /**
         * Sets the response type. Corresponds to the
         * {@code response_type} parameter.
         *
         * @param rt The response type. Must not be {@code null}.
         * @return This builder.
         */
        public Builder responseType(ResponseType rt) {

            if (rt == null) {
                throw new IllegalArgumentException("The response type must not be null");
            }

            this.rt = rt;
            return this;
        }


        /**
         * Sets the scope. Corresponds to the {@code scope} parameter.
         *
         * @param scope The scope. Must not be {@code null}.
         * @return This builder.
         */
        public Builder scope(Scope scope) {

            if (scope == null) {
                throw new IllegalArgumentException("The scope must not be null");
            }

            if (!scope.contains(OIDCScopeValue.OPENID)) {
                throw new IllegalArgumentException("The scope must include an \"openid\" value");
            }

            this.scope = scope;
            return this;
        }


        /**
         * Sets the client identifier. Corresponds to the
         * {@code client_id} parameter.
         *
         * @param clientID The client identifier. Must not be
         *                 {@code null}.
         * @return This builder.
         */
        public Builder clientID(ClientID clientID) {

            if (clientID == null) {
                throw new IllegalArgumentException("The client ID must not be null");
            }

            this.clientID = clientID;
            return this;
        }


        /**
         * Sets the redirection URI. Corresponds to the
         * {@code redirection_uri} parameter.
         *
         * @param redirectURI The redirection URI. Must not be
         *                    {@code null}.
         * @return This builder.
         */
        public Builder redirectionURI(URI redirectURI) {

            if (redirectURI == null) {
                throw new IllegalArgumentException("The redirection URI must not be null");
            }

            this.redirectURI = redirectURI;
            return this;
        }


        /**
         * Sets the state. Corresponds to the recommended {@code state}
         * parameter.
         *
         * @param state The state, {@code null} if not specified.
         * @return This builder.
         */
        public Builder state(State state) {

            this.state = state;
            return this;
        }


        /**
         * Sets the URI of the endpoint (HTTP or HTTPS) for which the
         * request is intended.
         *
         * @param uri The endpoint URI, {@code null} if not specified.
         * @return This builder.
         */
        public Builder endpointURI(URI uri) {

            this.uri = uri;
            return this;
        }


        /**
         * Sets the nonce. Corresponds to the conditionally optional
         * {@code nonce} parameter.
         *
         * @param nonce The nonce, {@code null} if not specified.
         * @return This builder.
         */
        public Builder nonce(Nonce nonce) {

            this.nonce = nonce;
            return this;
        }


        /**
         * Sets the requested display type. Corresponds to the optional
         * {@code display} parameter.
         *
         * @param display The requested display type, {@code null} if
         *                not specified.
         * @return This builder.
         */
        public Builder display(Display display) {

            this.display = display;
            return this;
        }


        /**
         * Sets the requested prompt. Corresponds to the optional
         * {@code prompt} parameter.
         *
         * @param prompt The requested prompt, {@code null} if not
         *               specified.
         * @return This builder.
         */
        public Builder prompt(Prompt prompt) {

            this.prompt = prompt;
            return this;
        }


        /**
         * Sets the required maximum authentication age. Corresponds to
         * the optional {@code max_age} parameter.
         *
         * @param maxAge The maximum authentication age, in seconds; 0
         *               if not specified.
         * @return This builder.
         */
        public Builder maxAge(int maxAge) {

            this.maxAge = maxAge;
            return this;
        }

        /**
         * Sets the ID Token hint. Corresponds to the conditionally
         * optional {@code id_token_hint} parameter.
         *
         * @param idTokenHint The ID Token hint, {@code null} if not
         *                    specified.
         * @return This builder.
         */
        public Builder idTokenHint(JWT idTokenHint) {

            this.idTokenHint = idTokenHint;
            return this;
        }


        /**
         * Sets the login hint. Corresponds to the optional
         * {@code login_hint} parameter.
         *
         * @param loginHint The login hint, {@code null} if not
         *                  specified.
         * @return This builder.
         */
        public Builder loginHint(String loginHint) {

            this.loginHint = loginHint;
            return this;
        }


        /**
         * Sets the requested Authentication Context Class Reference
         * values. Corresponds to the optional {@code acr_values}
         * parameter.
         *
         * @param acrValues The requested ACR values, {@code null} if
         *                  not specified.
         * @return This builder.
         */
        public Builder acrValues(List<ACR> acrValues) {

            this.acrValues = acrValues;
            return this;
        }


        /**
         * Sets the individual claims to be returned. Corresponds to
         * the optional {@code claims} parameter.
         *
         * @param claims The individual claims to be returned,
         *               {@code null} if not specified.
         * @return This builder.
         */
        public Builder claims(ClaimsRequest claims) {

            this.claims = claims;
            return this;
        }


        /**
         * Sets the request object. Corresponds to the optional
         * {@code request} parameter. Must not be specified together
         * with a request object URI.
         *
         * @param requestObject The request object, {@code null} if not
         *                      specified.
         * @return This builder.
         */
        public Builder requestObject(JWT requestObject) {

            this.requestObject = requestObject;
            return this;
        }


        /**
         * Sets the request object URI. Corresponds to the optional
         * {@code request_uri} parameter. Must not be specified
         * together with a request object.
         *
         * @param requestURI The request object URI, {@code null} if
         *                   not specified.
         * @return This builder.
         */
        public Builder requestURI(URI requestURI) {

            this.requestURI = requestURI;
            return this;
        }


        /**
         * Sets the response mode. Corresponds to the optional
         * {@code response_mode} parameter. Use of this parameter is
         * not recommended unless a non-default response mode is
         * requested (e.g. form_post).
         *
         * @param rm The response mode, {@code null} if not specified.
         * @return This builder.
         */
        public Builder responseMode(ResponseMode rm) {

            this.rm = rm;
            return this;
        }


        /**
         * Sets the code challenge for Proof Key for Code Exchange
         * (PKCE) by public OAuth clients.
         *
         * @param codeChallenge       The code challenge, {@code null}
         *                            if not specified.
         * @param codeChallengeMethod The code challenge method,
         *                            {@code null} if not specified.
         * @return This builder.
         */
        @Deprecated
        public Builder codeChallenge(CodeChallenge codeChallenge, CodeChallengeMethod codeChallengeMethod) {

            this.codeChallenge = codeChallenge;
            this.codeChallengeMethod = codeChallengeMethod;
            return this;
        }


        /**
         * Sets the code challenge for Proof Key for Code Exchange
         * (PKCE) by public OAuth clients.
         *
         * @param codeVerifier        The code verifier to use to
         *                            compute the code challenge,
         *                            {@code null} if PKCE is not
         *                            specified.
         * @param codeChallengeMethod The code challenge method,
         *                            {@code null} if not specified.
         *                            Defaults to
         *                            {@link CodeChallengeMethod#PLAIN}
         *                            if a code verifier is specified.
         * @return This builder.
         */
        public Builder codeChallenge(CodeVerifier codeVerifier, CodeChallengeMethod codeChallengeMethod) {

            if (codeVerifier != null) {
                CodeChallengeMethod method = codeChallengeMethod != null ? codeChallengeMethod : CodeChallengeMethod.getDefault();
                this.codeChallenge = CodeChallenge.compute(method, codeVerifier);
                this.codeChallengeMethod = method;
            } else {
                this.codeChallenge = null;
                this.codeChallengeMethod = null;
            }
            return this;
        }


        /**
         * Sets the resource server URI(s).
         *
         * @param resources The resource URI(s), {@code null} if not
         *                  specified.
         * @return This builder.
         */
        public Builder resources(URI... resources) {
            if (resources != null) {
                this.resources = Arrays.asList(resources);
            } else {
                this.resources = null;
            }
            return this;
        }


        /**
         * Requests incremental authorisation.
         *
         * @param includeGrantedScopes {@code true} to request
         *                             incremental authorisation.
         * @return This builder.
         */
        public Builder includeGrantedScopes(boolean includeGrantedScopes) {

            this.includeGrantedScopes = includeGrantedScopes;
            return this;
        }


        /**
         * Sets a custom parameter.
         *
         * @param name   The parameter name. Must not be {@code null}.
         * @param values The parameter values, {@code null} if not
         *               specified.
         * @return This builder.
         */
        public Builder customParameter(String name, String... values) {

            if (values == null || values.length == 0) {
                customParams.remove(name);
            } else {
                customParams.put(name, Arrays.asList(values));
            }

            return this;
        }


        /**
         * Builds a new authentication request.
         *
         * @return The authentication request.
         */
        public AuthenticationRequest build() {

            try {
                return new AuthenticationRequest(
                        uri, rt, rm, scope, clientID, redirectURI, state, nonce,
                        display, prompt, maxAge,
                        idTokenHint, loginHint, acrValues, claims,
                        requestObject, requestURI,
                        codeChallenge, codeChallengeMethod,
                        resources,
                        includeGrantedScopes,
                        customParams);

            } catch (IllegalArgumentException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }
    }


    /**
     * Creates a new minimal OpenID Connect authentication request.
     *
     * @param uri         The URI of the OAuth 2.0 authorisation endpoint.
     *                    May be {@code null} if the {@link #toHTTPRequest}
     *                    method will not be used.
     * @param rt          The response type. Corresponds to the
     *                    {@code response_type} parameter. Must specify a
     *                    valid OpenID Connect response type. Must not be
     *                    {@code null}.
     * @param scope       The request scope. Corresponds to the
     *                    {@code scope} parameter. Must contain an
     *                    {@link OIDCScopeValue#OPENID openid value}. Must
     *                    not be {@code null}.
     * @param clientID    The client identifier. Corresponds to the
     *                    {@code client_id} parameter. Must not be
     *                    {@code null}.
     * @param redirectURI The redirection URI. Corresponds to the
     *                    {@code redirect_uri} parameter. Must not be
     *                    {@code null}.
     * @param state       The state. Corresponds to the {@code state}
     *                    parameter. May be {@code null}.
     * @param nonce       The nonce. Corresponds to the {@code nonce}
     *                    parameter. May be {@code null} for code flow.
     */
    public AuthenticationRequest(URI uri,
                                 ResponseType rt,
                                 Scope scope,
                                 ClientID clientID,
                                 URI redirectURI,
                                 State state,
                                 Nonce nonce) {

        // Not specified: display, prompt, maxAge, uiLocales, claimsLocales,
        // idTokenHint, loginHint, acrValues, claims
        // codeChallenge, codeChallengeMethod
        this(uri, rt, null, scope, clientID, redirectURI, state, nonce,
                null, null, -1, null, null, null, null,
                null, null, null, null,
                null, false, null);
    }


    /**
     * Creates a new OpenID Connect authentication request with extension
     * and custom parameters.
     *
     * @param uri                  The URI of the OAuth 2.0 authorisation
     *                             endpoint. May be {@code null} if the
     *                             {@link #toHTTPRequest} method will not
     *                             be used.
     * @param rt                   The response type set. Corresponds to
     *                             the {@code response_type} parameter.
     *                             Must specify a valid OpenID Connect
     *                             response type. Must not be {@code null}.
     * @param rm                   The response mode. Corresponds to the
     *                             optional {@code response_mode}
     *                             parameter. Use of this parameter is not
     *                             recommended unless a non-default
     *                             response mode is requested (e.g.
     *                             form_post).
     * @param scope                The request scope. Corresponds to the
     *                             {@code scope} parameter. Must contain an
     *                             {@link OIDCScopeValue#OPENID openid
     *                             value}. Must not be {@code null}.
     * @param clientID             The client identifier. Corresponds to
     *                             the {@code client_id} parameter. Must
     *                             not be {@code null}.
     * @param redirectURI          The redirection URI. Corresponds to the
     *                             {@code redirect_uri} parameter. Must not
     *                             be {@code null} unless set by means of
     *                             the optional {@code request_object} /
     *                             {@code request_uri} parameter.
     * @param state                The state. Corresponds to the
     *                             recommended {@code state} parameter.
     *                             {@code null} if not specified.
     * @param nonce                The nonce. Corresponds to the
     *                             {@code nonce} parameter. May be
     *                             {@code null} for code flow.
     * @param display              The requested display type. Corresponds
     *                             to the optional {@code display}
     *                             parameter.
     *                             {@code null} if not specified.
     * @param prompt               The requested prompt. Corresponds to the
     *                             optional {@code prompt} parameter.
     *                             {@code null} if not specified.
     * @param maxAge               The required maximum authentication age,
     *                             in seconds. Corresponds to the optional
     *                             {@code max_age} parameter. -1 if not
     *                             specified, zero implies
     *                             {@code prompt=login}.
     * @param idTokenHint          The ID Token hint. Corresponds to the
     *                             optional {@code id_token_hint}
     *                             parameter. {@code null} if not
     *                             specified.
     * @param loginHint            The login hint. Corresponds to the
     *                             optional {@code login_hint} parameter.
     *                             {@code null} if not specified.
     * @param acrValues            The requested Authentication Context
     *                             Class Reference values. Corresponds to
     *                             the optional {@code acr_values}
     *                             parameter. {@code null} if not
     *                             specified.
     * @param claims               The individual claims to be returned.
     *                             Corresponds to the optional
     *                             {@code claims} parameter. {@code null}
     *                             if not specified.
     * @param requestObject        The request object. Corresponds to the
     *                             optional {@code request} parameter. Must
     *                             not be specified together with a request
     *                             object URI. {@code null} if not
     *                             specified.
     * @param requestURI           The request object URI. Corresponds to
     *                             the optional {@code request_uri}
     *                             parameter. Must not be specified
     *                             together with a request object.
     *                             {@code null} if not specified.
     * @param codeChallenge        The code challenge for PKCE,
     *                             {@code null} if not specified.
     * @param codeChallengeMethod  The code challenge method for PKCE,
     *                             {@code null} if not specified.
     * @param resources            The resource URI(s), {@code null} if not
     *                             specified.
     * @param includeGrantedScopes {@code true} to request incremental
     *                             authorisation.
     * @param customParams         Additional custom parameters, empty map
     *                             or {@code null} if none.
     */
    public AuthenticationRequest(URI uri,
                                 ResponseType rt,
                                 ResponseMode rm,
                                 Scope scope,
                                 ClientID clientID,
                                 URI redirectURI,
                                 State state,
                                 Nonce nonce,
                                 Display display,
                                 Prompt prompt,
                                 int maxAge,
                                 JWT idTokenHint,
                                 String loginHint,
                                 List<ACR> acrValues,
                                 ClaimsRequest claims,
                                 JWT requestObject,
                                 URI requestURI,
                                 CodeChallenge codeChallenge,
                                 CodeChallengeMethod codeChallengeMethod,
                                 List<URI> resources,
                                 boolean includeGrantedScopes,
                                 Map<String, List<String>> customParams) {

        super(uri, rt, rm, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, resources, includeGrantedScopes, requestObject, requestURI, prompt, customParams);

        if (!specifiesRequestObject()) {

            // Check parameters required by OpenID Connect if no JAR

            if (redirectURI == null) {
                throw new IllegalArgumentException("The redirection URI must not be null");
            }

            OIDCResponseTypeValidator.validate(rt);

            if (scope == null) {
                throw new IllegalArgumentException("The scope must not be null");
            }

            if (!scope.contains(OIDCScopeValue.OPENID)) {
                throw new IllegalArgumentException("The scope must include an \"openid\" value");
            }

            // Nonce required in the implicit and hybrid flows
            if (nonce == null && (rt.impliesImplicitFlow() || rt.impliesHybridFlow())) {
                throw new IllegalArgumentException("Nonce is required in implicit / hybrid protocol flow");
            }
        }

        this.nonce = nonce;

        // Optional parameters
        this.display = display;
        this.maxAge = maxAge;

        this.idTokenHint = idTokenHint;
        this.loginHint = loginHint;

        if (acrValues != null) {
            this.acrValues = Collections.unmodifiableList(acrValues);
        } else {
            this.acrValues = null;
        }

        this.claims = claims;
    }


    /**
     * Returns the registered (standard) OpenID Connect authentication
     * request parameter names.
     *
     * @return The registered OpenID Connect authentication request
     * parameter names, as a unmodifiable set.
     */
    public static Set<String> getRegisteredParameterNames() {

        return REGISTERED_PARAMETER_NAMES;
    }


    /**
     * Gets the nonce. Corresponds to the conditionally optional
     * {@code nonce} parameter.
     *
     * @return The nonce, {@code null} if not specified.
     */
    public Nonce getNonce() {

        return nonce;
    }


    /**
     * Gets the requested display type. Corresponds to the optional
     * {@code display} parameter.
     *
     * @return The requested display type, {@code null} if not specified.
     */
    public Display getDisplay() {

        return display;
    }


    /**
     * Gets the required maximum authentication age. Corresponds to the
     * optional {@code max_age} parameter.
     *
     * @return The maximum authentication age, in seconds; -1 if not
     * specified, zero implies {@code prompt=login}.
     */
    public int getMaxAge() {

        return maxAge;
    }


    /**
     * Gets the ID Token hint. Corresponds to the conditionally optional
     * {@code id_token_hint} parameter.
     *
     * @return The ID Token hint, {@code null} if not specified.
     */
    public JWT getIDTokenHint() {

        return idTokenHint;
    }


    /**
     * Gets the login hint. Corresponds to the optional {@code login_hint}
     * parameter.
     *
     * @return The login hint, {@code null} if not specified.
     */
    public String getLoginHint() {

        return loginHint;
    }


    /**
     * Gets the requested Authentication Context Class Reference values.
     * Corresponds to the optional {@code acr_values} parameter.
     *
     * @return The requested ACR values, {@code null} if not specified.
     */
    public List<ACR> getACRValues() {

        return acrValues;
    }


    /**
     * Gets the individual claims to be returned. Corresponds to the
     * optional {@code claims} parameter.
     *
     * @return The individual claims to be returned, {@code null} if not
     * specified.
     */
    public ClaimsRequest getClaims() {

        return claims;
    }


    @Override
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = super.toParameters();

        if (nonce != null) {
            params.put("nonce", Collections.singletonList(nonce.toString()));
        }

        if (display != null) {
            params.put("display", Collections.singletonList(display.toString()));
        }

        if (maxAge >= 0) {
            params.put("max_age", Collections.singletonList("" + maxAge));
        }

        if (idTokenHint != null) {

            try {
                params.put("id_token_hint", Collections.singletonList(idTokenHint.serialize()));

            } catch (IllegalStateException e) {

                throw new SerializeException("Couldn't serialize ID token hint: " + e.getMessage(), e);
            }
        }

        if (loginHint != null) {
            params.put("login_hint", Collections.singletonList(loginHint));
        }

        if (acrValues != null) {

            StringBuilder sb = new StringBuilder();

            for (ACR acr : acrValues) {

                if (sb.length() > 0) {
                    sb.append(' ');
                }

                sb.append(acr.toString());
            }

            params.put("acr_values", Collections.singletonList(sb.toString()));
        }


        if (claims != null) {
            params.put("claims", Collections.singletonList(claims.toJSONObject().toString()));
        }

        return params;
    }


    @Override
    public JWTClaimsSet toJWTClaimsSet() {

        JWTClaimsSet jwtClaimsSet = super.toJWTClaimsSet();

        if (jwtClaimsSet.getClaim("max_age") != null) {
            // Convert max_age to number in JSON object
            try {
                String maxAgeString = jwtClaimsSet.getStringClaim("max_age");
                JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder(jwtClaimsSet);
                builder.claim("max_age", Integer.parseInt(maxAgeString));
                return builder.build();
            } catch (java.text.ParseException e) {
                throw new SerializeException(e.getMessage());
            }
        }

        return jwtClaimsSet;
    }


    /**
     * Parses an OpenID Connect authentication request from the specified
     * URI query parameters.
     *
     * <p>Example parameters:
     *
     * <pre>
     * response_type = token id_token
     * client_id     = s6BhdRkqt3
     * redirect_uri  = https://client.example.com/cb
     * scope         = openid profile
     * state         = af0ifjsldkj
     * nonce         = -0S6_WzA2Mj
     * </pre>
     *
     * @param params The parameters. Must not be {@code null}.
     * @return The OpenID Connect authentication request.
     * @throws OAuth2JSONParseException If the parameters couldn't be parsed to an
     *                                  OpenID Connect authentication request.
     */
    public static AuthenticationRequest parse(Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        return parse(null, params);
    }


    /**
     * Parses an OpenID Connect authentication request from the specified
     * URI and query parameters.
     *
     * <p>Example parameters:
     *
     * <pre>
     * response_type = token id_token
     * client_id     = s6BhdRkqt3
     * redirect_uri  = https://client.example.com/cb
     * scope         = openid profile
     * state         = af0ifjsldkj
     * nonce         = -0S6_WzA2Mj
     * </pre>
     *
     * @param uri    The URI of the OAuth 2.0 authorisation endpoint. May
     *               be {@code null} if the {@link #toHTTPRequest} method
     *               will not be used.
     * @param params The parameters. Must not be {@code null}.
     * @return The OpenID Connect authentication request.
     * @throws OAuth2JSONParseException If the parameters couldn't be parsed to an
     *                                  OpenID Connect authentication request.
     */
    public static AuthenticationRequest parse(URI uri, Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        // Parse and validate the core OAuth 2.0 autz request params in
        // the context of OIDC
        AuthorizationRequest ar = AuthorizationRequest.parse(uri, params);

        Nonce nonce = Nonce.parse(MultivaluedMapUtils.getFirstValue(params, "nonce"));

        if (!ar.specifiesRequestObject()) {

            // Required params if no JAR is present

            if (ar.getRedirectionURI() == null) {
                String msg = "Missing \"redirect_uri\" parameter";
                throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
                        ar.getClientID(), null, ar.impliedResponseMode(), ar.getState());
            }

            if (ar.getScope() == null) {
                String msg = "Missing \"scope\" parameter";
                throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
                        ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState());
            }

            // Nonce required in the implicit and hybrid flows
            if (nonce == null && (ar.getResponseType().impliesImplicitFlow() || ar.getResponseType().impliesHybridFlow())) {
                String msg = "Missing \"nonce\" parameter: Required in the implicit and hybrid flows";
                throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
                        ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState());
            }
        }

        // Check if present (not in JAR)
        if (ar.getResponseType() != null) {
            try {
                OIDCResponseTypeValidator.validate(ar.getResponseType());
            } catch (IllegalArgumentException e) {
                String msg = "Unsupported \"response_type\" parameter: " + e.getMessage();
                throw new OAuth2JSONParseException(msg, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE.appendDescription(": " + msg),
                        ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState());
            }
        }

        // Check if present (not in JAR)
        if (ar.getScope() != null && !ar.getScope().contains(OIDCScopeValue.OPENID)) {
            String msg = "The scope must include an \"openid\" value";
            throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
                    ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState());
        }

        Display display = null;

        if (params.containsKey("display")) {
            try {
                display = Display.parse(MultivaluedMapUtils.getFirstValue(params, "display"));

            } catch (OAuth2JSONParseException e) {
                String msg = "Invalid \"display\" parameter: " + e.getMessage();
                throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
                        ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState(), e);
            }
        }


        String v = MultivaluedMapUtils.getFirstValue(params, "max_age");

        int maxAge = -1;

        if (StringUtils.hasText(v)) {

            try {
                maxAge = Integer.parseInt(v);

            } catch (NumberFormatException e) {
                String msg = "Invalid \"max_age\" parameter: " + v;
                throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
                        ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState(), e);
            }
        }

        v = MultivaluedMapUtils.getFirstValue(params, "id_token_hint");

        JWT idTokenHint = null;

        if (StringUtils.hasText(v)) {

            try {
                idTokenHint = JWTParser.parse(v);

            } catch (java.text.ParseException e) {
                String msg = "Invalid \"id_token_hint\" parameter: " + e.getMessage();
                throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
                        ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState(), e);
            }
        }

        String loginHint = MultivaluedMapUtils.getFirstValue(params, "login_hint");


        v = MultivaluedMapUtils.getFirstValue(params, "acr_values");

        List<ACR> acrValues = null;

        if (StringUtils.hasText(v)) {

            acrValues = new LinkedList<>();

            StringTokenizer st = new StringTokenizer(v, " ");

            while (st.hasMoreTokens()) {

                acrValues.add(new ACR(st.nextToken()));
            }
        }


        v = MultivaluedMapUtils.getFirstValue(params, "claims");

        ClaimsRequest claims = null;

        if (StringUtils.hasText(v)) {

            JsonObject jsonObject;

            try {
                jsonObject = JSONObjectUtils.parse(v);

            } catch (ParseException e) {
                String msg = "Invalid \"claims\" parameter: " + e.getMessage();
                throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
                        ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState(), e);
            }

            // Parse exceptions silently ignored
            claims = ClaimsRequest.parse(jsonObject);
        }

        // Parse additional custom parameters
        Map<String, List<String>> customParams = null;

        for (Map.Entry<String, List<String>> p : params.entrySet()) {

            if (!REGISTERED_PARAMETER_NAMES.contains(p.getKey())) {
                // We have a custom parameter
                if (customParams == null) {
                    customParams = new HashMap<>();
                }
                customParams.put(p.getKey(), p.getValue());
            }
        }


        return new AuthenticationRequest(
                uri, ar.getResponseType(), ar.getResponseMode(), ar.getScope(), ar.getClientID(), ar.getRedirectionURI(), ar.getState(), nonce,
                display, ar.getPrompt(), maxAge,
                idTokenHint, loginHint, acrValues, claims,
                ar.getRequestObject(), ar.getRequestURI(),
                ar.getCodeChallenge(), ar.getCodeChallengeMethod(),
                ar.getResources(),
                ar.includeGrantedScopes(),
                customParams);
    }


    /**
     * Parses an OpenID Connect authentication request from the specified
     * URI query string.
     *
     * <p>Example URI query string:
     *
     * <pre>
     * response_type=token%20id_token
     * &amp;client_id=s6BhdRkqt3
     * &amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
     * &amp;scope=openid%20profile
     * &amp;state=af0ifjsldkj
     * &amp;nonce=n-0S6_WzA2Mj
     * </pre>
     *
     * @param query The URI query string. Must not be {@code null}.
     * @return The OpenID Connect authentication request.
     * @throws OAuth2JSONParseException If the query string couldn't be parsed to an
     *                                  OpenID Connect authentication request.
     */
    public static AuthenticationRequest parse(String query)
            throws OAuth2JSONParseException {

        return parse(null, URLUtils.parseParameters(query));
    }


    /**
     * Parses an OpenID Connect authentication request from the specified
     * URI query string.
     *
     * <p>Example URI query string:
     *
     * <pre>
     * response_type=token%20id_token
     * &amp;client_id=s6BhdRkqt3
     * &amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
     * &amp;scope=openid%20profile
     * &amp;state=af0ifjsldkj
     * &amp;nonce=n-0S6_WzA2Mj
     * </pre>
     *
     * @param uri   The URI of the OAuth 2.0 authorisation endpoint. May be
     *              {@code null} if the {@link #toHTTPRequest} method will
     *              not be used.
     * @param query The URI query string. Must not be {@code null}.
     * @return The OpenID Connect authentication request.
     * @throws OAuth2JSONParseException If the query string couldn't be parsed to an
     *                                  OpenID Connect authentication request.
     */
    public static AuthenticationRequest parse(URI uri, String query)
            throws OAuth2JSONParseException {

        return parse(uri, URLUtils.parseParameters(query));
    }


    /**
     * Parses an OpenID Connect authentication request from the specified
     * URI.
     *
     * <p>Example URI:
     *
     * <pre>
     * https://server.example.com/authorize?
     * response_type=token%20id_token
     * &amp;client_id=s6BhdRkqt3
     * &amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
     * &amp;scope=openid%20profile
     * &amp;state=af0ifjsldkj
     * &amp;nonce=n-0S6_WzA2Mj
     * </pre>
     *
     * @param uri The URI. Must not be {@code null}.
     * @return The OpenID Connect authentication request.
     * @throws OAuth2JSONParseException If the query string couldn't be parsed to an
     *                                  OpenID Connect authentication request.
     */
    public static AuthenticationRequest parse(URI uri)
            throws OAuth2JSONParseException {

        return parse(URIUtils.getBaseURI(uri), URLUtils.parseParameters(uri.getRawQuery()));
    }


    /**
     * Parses an authentication request from the specified HTTP GET or HTTP
     * POST request.
     *
     * <p>Example HTTP request (GET):
     *
     * <pre>
     * https://server.example.com/op/authorize?
     * response_type=code%20id_token
     * &amp;client_id=s6BhdRkqt3
     * &amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
     * &amp;scope=openid
     * &amp;nonce=n-0S6_WzA2Mj
     * &amp;state=af0ifjsldkj
     * </pre>
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The OpenID Connect authentication request.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to an
     *                                  OpenID Connect authentication request.
     */
    public static AuthenticationRequest parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        String query = httpRequest.getQuery();

        if (query == null) {
            throw new OAuth2JSONParseException("Missing URI query string");
        }

        URI endpointURI;

        try {
            endpointURI = httpRequest.getURL().toURI();

        } catch (URISyntaxException e) {

            throw new OAuth2JSONParseException(e.getMessage(), e);
        }

        return parse(endpointURI, query);
    }
}
