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
package be.atbash.ee.oauth2.sdk.as;


import be.atbash.ee.langtag.LangTag;
import be.atbash.ee.langtag.LangTagException;
import be.atbash.ee.oauth2.sdk.*;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.pkce.CodeChallengeMethod;
import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.*;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.ParseException;
import java.util.*;


/**
 * OAuth 2.0 Authorisation Server (AS) metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Authorization Server Metadata (RFC 8414)
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (draft-ietf-oauth-mtls-15)
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 *     <li>Financial-grade API - Part 2: Read and Write API Security Profile
 *     <li>OAuth 2.0 Pushed Authorization Requests
 *         (draft-lodderstedt-oauth-par-01)
 *     <li>OAuth 2.0 Device Flow for Browserless and Input Constrained Devices
 *         (draft-ietf-oauth-device-flow-14)
 * </ul>
 */
public class AuthorizationServerMetadata extends AuthorizationServerEndpointMetadata {

    /**
     * The registered parameter names.
     */
    private static final Set<String> REGISTERED_PARAMETER_NAMES;


    static {
        Set<String> p = new HashSet<>(AuthorizationServerEndpointMetadata.getRegisteredParameterNames());
        p.add("issuer");
        p.add("jwks_uri");
        p.add("scopes_supported");
        p.add("response_types_supported");
        p.add("response_modes_supported");
        p.add("grant_types_supported");
        p.add("code_challenge_methods_supported");
        p.add("token_endpoint_auth_methods_supported");
        p.add("token_endpoint_auth_signing_alg_values_supported");
        p.add("request_parameter_supported");
        p.add("request_uri_parameter_supported");
        p.add("require_request_uri_registration");
        p.add("request_object_signing_alg_values_supported");
        p.add("request_object_encryption_alg_values_supported");
        p.add("request_object_encryption_enc_values_supported");
        p.add("ui_locales_supported");
        p.add("service_documentation");
        p.add("op_policy_uri");
        p.add("op_tos_uri");
        p.add("introspection_endpoint_auth_methods_supported");
        p.add("introspection_endpoint_auth_signing_alg_values_supported");
        p.add("revocation_endpoint_auth_methods_supported");
        p.add("revocation_endpoint_auth_signing_alg_values_supported");
        p.add("mtls_endpoint_aliases");
        p.add("tls_client_certificate_bound_access_tokens");
        p.add("authorization_signing_alg_values_supported");
        p.add("authorization_encryption_alg_values_supported");
        p.add("authorization_encryption_enc_values_supported");
        REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
    }


    /**
     * Gets the registered OpenID Connect provider metadata parameter
     * names.
     *
     * @return The registered OpenID Connect provider metadata parameter
     * names, as an unmodifiable set.
     */
    public static Set<String> getRegisteredParameterNames() {

        return REGISTERED_PARAMETER_NAMES;
    }


    /**
     * The issuer.
     */
    private final Issuer issuer;


    /**
     * The JWK set URI.
     */
    private URI jwkSetURI;


    /**
     * The supported scope values.
     */
    private Scope scope;


    /**
     * The supported response types.
     */
    private List<ResponseType> rts;


    /**
     * The supported response modes.
     */
    private List<ResponseMode> rms;


    /**
     * The supported grant types.
     */
    private List<GrantType> gts;


    /**
     * The supported code challenge methods for PKCE.
     */
    private List<CodeChallengeMethod> codeChallengeMethods;


    /**
     * The supported token endpoint authentication methods.
     */
    private List<ClientAuthenticationMethod> tokenEndpointAuthMethods;


    /**
     * The supported JWS algorithms for the {@code private_key_jwt} and
     * {@code client_secret_jwt} token endpoint authentication methods.
     */
    private List<JWSAlgorithm> tokenEndpointJWSAlgs;


    /**
     * The supported introspection endpoint authentication methods.
     */
    private List<ClientAuthenticationMethod> introspectionEndpointAuthMethods;


    /**
     * The supported JWS algorithms for the {@code private_key_jwt} and
     * {@code client_secret_jwt} introspection endpoint authentication
     * methods.
     */
    private List<JWSAlgorithm> introspectionEndpointJWSAlgs;


    /**
     * The supported revocation endpoint authentication methods.
     */
    private List<ClientAuthenticationMethod> revocationEndpointAuthMethods;


    /**
     * The supported JWS algorithms for the {@code private_key_jwt} and
     * {@code client_secret_jwt} revocation endpoint authentication
     * methods.
     */
    private List<JWSAlgorithm> revocationEndpointJWSAlgs;


    /**
     * The supported JWS algorithms for request objects.
     */
    private List<JWSAlgorithm> requestObjectJWSAlgs;


    /**
     * The supported JWE algorithms for request objects.
     */
    private List<JWEAlgorithm> requestObjectJWEAlgs;


    /**
     * The supported encryption methods for request objects.
     */
    private List<EncryptionMethod> requestObjectJWEEncs;


    /**
     * If {@code true} the {@code request} parameter is supported, else
     * not.
     */
    private boolean requestParamSupported = false;


    /**
     * If {@code true} the {@code request_uri} parameter is supported, else
     * not.
     */
    private boolean requestURIParamSupported = false;


    /**
     * If {@code true} the {@code request_uri} parameters must be
     * pre-registered with the provider, else not.
     */
    private boolean requireRequestURIReg = false;


    /**
     * The supported UI locales.
     */
    private List<LangTag> uiLocales;


    /**
     * The service documentation URI.
     */
    private URI serviceDocsURI;


    /**
     * The provider's policy regarding relying party use of data.
     */
    private URI policyURI;


    /**
     * The provider's terms of service.
     */
    private URI tosURI;


    /**
     * Aliases for endpoints with mutial TLS authentication.
     */
    private AuthorizationServerEndpointMetadata mtlsEndpointAliases;


    /**
     * If {@code true} the
     * {@code tls_client_certificate_bound_access_tokens} if set, else
     * not.
     */
    private boolean tlsClientCertificateBoundAccessTokens = false;


    /**
     * The supported JWS algorithms for JWT-encoded authorisation
     * responses.
     */
    private List<JWSAlgorithm> authzJWSAlgs;


    /**
     * The supported JWE algorithms for JWT-encoded authorisation
     * responses.
     */
    private List<JWEAlgorithm> authzJWEAlgs;


    /**
     * The supported encryption methods for JWT-encoded authorisation
     * responses.
     */
    private List<EncryptionMethod> authzJWEEncs;


    private URI parEndpoint;


    /**
     * Custom (not-registered) parameters.
     */
    private JsonObjectBuilder customParametersBuilder = Json.createObjectBuilder();

    private JsonObject customParameters;


    /**
     * Creates a new OAuth 2.0 Authorisation Server (AS) metadata instance.
     *
     * @param issuer The issuer identifier. Must be an URI using the https
     *               scheme with no query or fragment component. Must not
     *               be {@code null}.
     */
    public AuthorizationServerMetadata(Issuer issuer) {

        URI uri;
        try {
            uri = new URI(issuer.getValue());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("The issuer identifier must be a URI: " + e.getMessage(), e);
        }

        if (uri.getRawQuery() != null) {
            throw new IllegalArgumentException("The issuer URI must be without a query component");
        }

        if (uri.getRawFragment() != null) {
            throw new IllegalArgumentException("The issuer URI must be without a fragment component");
        }

        this.issuer = issuer;
    }


    /**
     * Gets the issuer identifier. Corresponds to the {@code issuer}
     * metadata field.
     *
     * @return The issuer identifier.
     */
    public Issuer getIssuer() {

        return issuer;
    }


    /**
     * Gets the JSON Web Key (JWK) set URI. Corresponds to the
     * {@code jwks_uri} metadata field.
     *
     * @return The JWK set URI, {@code null} if not specified.
     */
    public URI getJWKSetURI() {

        return jwkSetURI;
    }


    /**
     * Sets the JSON Web Key (JWT) set URI. Corresponds to the
     * {@code jwks_uri} metadata field.
     *
     * @param jwkSetURI The JWK set URI, {@code null} if not specified.
     */
    public void setJWKSetURI(URI jwkSetURI) {

        this.jwkSetURI = jwkSetURI;
    }


    /**
     * Gets the supported scope values. Corresponds to the
     * {@code scopes_supported} metadata field.
     *
     * @return The supported scope values, {@code null} if not specified.
     */
    public Scope getScopes() {

        return scope;
    }


    /**
     * Sets the supported scope values. Corresponds to the
     * {@code scopes_supported} metadata field.
     *
     * @param scope The supported scope values, {@code null} if not
     *              specified.
     */
    public void setScopes(Scope scope) {

        this.scope = scope;
    }


    /**
     * Gets the supported response type values. Corresponds to the
     * {@code response_types_supported} metadata field.
     *
     * @return The supported response type values, {@code null} if not
     * specified.
     */
    public List<ResponseType> getResponseTypes() {

        return rts;
    }


    /**
     * Sets the supported response type values. Corresponds to the
     * {@code response_types_supported} metadata field.
     *
     * @param rts The supported response type values, {@code null} if not
     *            specified.
     */
    public void setResponseTypes(List<ResponseType> rts) {

        this.rts = rts;
    }


    /**
     * Gets the supported response mode values. Corresponds to the
     * {@code response_modes_supported}.
     *
     * @return The supported response mode values, {@code null} if not
     * specified.
     */
    public List<ResponseMode> getResponseModes() {

        return rms;
    }


    /**
     * Sets the supported response mode values. Corresponds to the
     * {@code response_modes_supported}.
     *
     * @param rms The supported response mode values, {@code null} if not
     *            specified.
     */
    public void setResponseModes(List<ResponseMode> rms) {

        this.rms = rms;
    }


    /**
     * Gets the supported OAuth 2.0 grant types. Corresponds to the
     * {@code grant_types_supported} metadata field.
     *
     * @return The supported grant types, {@code null} if not specified.
     */
    public List<GrantType> getGrantTypes() {

        return gts;
    }


    /**
     * Sets the supported OAuth 2.0 grant types. Corresponds to the
     * {@code grant_types_supported} metadata field.
     *
     * @param gts The supported grant types, {@code null} if not specified.
     */
    public void setGrantTypes(List<GrantType> gts) {

        this.gts = gts;
    }


    /**
     * Gets the supported authorisation code challenge methods for PKCE.
     * Corresponds to the {@code code_challenge_methods_supported} metadata
     * field.
     *
     * @return The supported code challenge methods, {@code null} if not
     * specified.
     */
    public List<CodeChallengeMethod> getCodeChallengeMethods() {

        return codeChallengeMethods;
    }


    /**
     * Gets the supported authorisation code challenge methods for PKCE.
     * Corresponds to the {@code code_challenge_methods_supported} metadata
     * field.
     *
     * @param codeChallengeMethods The supported code challenge methods,
     *                             {@code null} if not specified.
     */
    public void setCodeChallengeMethods(List<CodeChallengeMethod> codeChallengeMethods) {

        this.codeChallengeMethods = codeChallengeMethods;
    }


    /**
     * Gets the supported token endpoint authentication methods.
     * Corresponds to the {@code token_endpoint_auth_methods_supported}
     * metadata field.
     *
     * @return The supported token endpoint authentication methods,
     * {@code null} if not specified.
     */
    public List<ClientAuthenticationMethod> getTokenEndpointAuthMethods() {

        return tokenEndpointAuthMethods;
    }


    /**
     * Sets the supported token endpoint authentication methods.
     * Corresponds to the {@code token_endpoint_auth_methods_supported}
     * metadata field.
     *
     * @param authMethods The supported token endpoint authentication
     *                    methods, {@code null} if not specified.
     */
    public void setTokenEndpointAuthMethods(List<ClientAuthenticationMethod> authMethods) {

        this.tokenEndpointAuthMethods = authMethods;
    }


    /**
     * Gets the supported JWS algorithms for the {@code private_key_jwt}
     * and {@code client_secret_jwt} token endpoint authentication methods.
     * Corresponds to the
     * {@code token_endpoint_auth_signing_alg_values_supported} metadata
     * field.
     *
     * @return The supported JWS algorithms, {@code null} if not specified.
     */
    public List<JWSAlgorithm> getTokenEndpointJWSAlgs() {

        return tokenEndpointJWSAlgs;
    }


    /**
     * Sets the supported JWS algorithms for the {@code private_key_jwt}
     * and {@code client_secret_jwt} token endpoint authentication methods.
     * Corresponds to the
     * {@code token_endpoint_auth_signing_alg_values_supported} metadata
     * field.
     *
     * @param jwsAlgs The supported JWS algorithms, {@code null} if not
     *                specified. Must not contain the {@code none}
     *                algorithm.
     */
    public void setTokenEndpointJWSAlgs(List<JWSAlgorithm> jwsAlgs) {

        if (jwsAlgs != null && jwsAlgs.contains(Algorithm.NONE)) {
            throw new IllegalArgumentException("The \"none\" algorithm is not accepted");
        }

        this.tokenEndpointJWSAlgs = jwsAlgs;
    }


    /**
     * Gets the supported introspection endpoint authentication methods.
     * Corresponds to the
     * {@code introspection_endpoint_auth_methods_supported} metadata
     * field.
     *
     * @return The supported introspection endpoint authentication methods,
     * {@code null} if not specified.
     */
    public List<ClientAuthenticationMethod> getIntrospectionEndpointAuthMethods() {
        return introspectionEndpointAuthMethods;
    }


    /**
     * Sets the supported introspection endpoint authentication methods.
     * Corresponds to the
     * {@code introspection_endpoint_auth_methods_supported} metadata
     * field.
     *
     * @param authMethods The supported introspection endpoint
     *                    authentication methods, {@code null} if not
     *                    specified.
     */
    public void setIntrospectionEndpointAuthMethods(List<ClientAuthenticationMethod> authMethods) {

        this.introspectionEndpointAuthMethods = authMethods;
    }


    /**
     * Gets the supported JWS algorithms for the {@code private_key_jwt}
     * and {@code client_secret_jwt} introspection endpoint authentication
     * methods. Corresponds to the
     * {@code introspection_endpoint_auth_signing_alg_values_supported}
     * metadata field.
     *
     * @return The supported JWS algorithms, {@code null} if not specified.
     */
    public List<JWSAlgorithm> getIntrospectionEndpointJWSAlgs() {

        return introspectionEndpointJWSAlgs;
    }


    /**
     * Sets the supported JWS algorithms for the {@code private_key_jwt}
     * and {@code client_secret_jwt} introspection endpoint authentication
     * methods. Corresponds to the
     * {@code introspection_endpoint_auth_signing_alg_values_supported}
     * metadata field.
     *
     * @param jwsAlgs The supported JWS algorithms, {@code null} if not
     *                specified. Must not contain the {@code none}
     *                algorithm.
     */
    public void setIntrospectionEndpointJWSAlgs(List<JWSAlgorithm> jwsAlgs) {

        if (jwsAlgs != null && jwsAlgs.contains(Algorithm.NONE)) {
            throw new IllegalArgumentException("The \"none\" algorithm is not accepted");
        }

        introspectionEndpointJWSAlgs = jwsAlgs;
    }


    /**
     * Gets the supported revocation endpoint authentication methods.
     * Corresponds to the
     * {@code revocation_endpoint_auth_methods_supported} metadata field.
     *
     * @return The supported revocation endpoint authentication methods,
     * {@code null} if not specified.
     */
    public List<ClientAuthenticationMethod> getRevocationEndpointAuthMethods() {

        return revocationEndpointAuthMethods;
    }


    /**
     * Sets the supported revocation endpoint authentication methods.
     * Corresponds to the
     * {@code revocation_endpoint_auth_methods_supported} metadata field.
     *
     * @param authMethods The supported revocation endpoint authentication
     *                    methods, {@code null} if not specified.
     */
    public void setRevocationEndpointAuthMethods(List<ClientAuthenticationMethod> authMethods) {

        revocationEndpointAuthMethods = authMethods;
    }


    /**
     * Gets the supported JWS algorithms for the {@code private_key_jwt}
     * and {@code client_secret_jwt} revocation endpoint authentication
     * methods. Corresponds to the
     * {@code revocation_endpoint_auth_signing_alg_values_supported}
     * metadata field.
     *
     * @return The supported JWS algorithms, {@code null} if not specified.
     */
    public List<JWSAlgorithm> getRevocationEndpointJWSAlgs() {

        return revocationEndpointJWSAlgs;
    }


    /**
     * Sets the supported JWS algorithms for the {@code private_key_jwt}
     * and {@code client_secret_jwt} revocation endpoint authentication
     * methods. Corresponds to the
     * {@code revocation_endpoint_auth_signing_alg_values_supported}
     * metadata field.
     *
     * @param jwsAlgs The supported JWS algorithms, {@code null} if not
     *                specified. Must not contain the {@code none}
     *                algorithm.
     */
    public void setRevocationEndpointJWSAlgs(final List<JWSAlgorithm> jwsAlgs) {

        if (jwsAlgs != null && jwsAlgs.contains(Algorithm.NONE)) {
            throw new IllegalArgumentException("The \"none\" algorithm is not accepted");
        }

        revocationEndpointJWSAlgs = jwsAlgs;
    }


    /**
     * Gets the supported JWS algorithms for request objects. Corresponds
     * to the {@code request_object_signing_alg_values_supported} metadata
     * field.
     *
     * @return The supported JWS algorithms, {@code null} if not specified.
     */
    public List<JWSAlgorithm> getRequestObjectJWSAlgs() {

        return requestObjectJWSAlgs;
    }


    /**
     * Sets the supported JWS algorithms for request objects. Corresponds
     * to the {@code request_object_signing_alg_values_supported} metadata
     * field.
     *
     * @param requestObjectJWSAlgs The supported JWS algorithms,
     *                             {@code null} if not specified.
     */
    public void setRequestObjectJWSAlgs(List<JWSAlgorithm> requestObjectJWSAlgs) {

        this.requestObjectJWSAlgs = requestObjectJWSAlgs;
    }


    /**
     * Gets the supported JWE algorithms for request objects. Corresponds
     * to the {@code request_object_encryption_alg_values_supported}
     * metadata field.
     *
     * @return The supported JWE algorithms, {@code null} if not specified.
     */
    public List<JWEAlgorithm> getRequestObjectJWEAlgs() {

        return requestObjectJWEAlgs;
    }


    /**
     * Sets the supported JWE algorithms for request objects. Corresponds
     * to the {@code request_object_encryption_alg_values_supported}
     * metadata field.
     *
     * @param requestObjectJWEAlgs The supported JWE algorithms,
     *                             {@code null} if not specified.
     */
    public void setRequestObjectJWEAlgs(List<JWEAlgorithm> requestObjectJWEAlgs) {

        this.requestObjectJWEAlgs = requestObjectJWEAlgs;
    }


    /**
     * Gets the supported encryption methods for request objects.
     * Corresponds to the
     * {@code request_object_encryption_enc_values_supported} metadata
     * field.
     *
     * @return The supported encryption methods, {@code null} if not
     * specified.
     */
    public List<EncryptionMethod> getRequestObjectJWEEncs() {

        return requestObjectJWEEncs;
    }


    /**
     * Sets the supported encryption methods for request objects.
     * Corresponds to the
     * {@code request_object_encryption_enc_values_supported} metadata
     * field.
     *
     * @param requestObjectJWEEncs The supported encryption methods,
     *                             {@code null} if not specified.
     */
    public void setRequestObjectJWEEncs(List<EncryptionMethod> requestObjectJWEEncs) {

        this.requestObjectJWEEncs = requestObjectJWEEncs;
    }


    /**
     * Gets the support for the {@code request} authorisation request
     * parameter. Corresponds to the {@code request_parameter_supported}
     * metadata field.
     *
     * @return {@code true} if the {@code reqeust} parameter is supported,
     * else {@code false}.
     */
    public boolean supportsRequestParam() {

        return requestParamSupported;
    }


    /**
     * Sets the support for the {@code request} authorisation request
     * parameter. Corresponds to the {@code request_parameter_supported}
     * metadata field.
     *
     * @param requestParamSupported {@code true} if the {@code reqeust}
     *                              parameter is supported, else
     *                              {@code false}.
     */
    public void setSupportsRequestParam(boolean requestParamSupported) {

        this.requestParamSupported = requestParamSupported;
    }


    /**
     * Gets the support for the {@code request_uri} authorisation request
     * parameter. Corresponds the {@code request_uri_parameter_supported}
     * metadata field.
     *
     * @return {@code true} if the {@code request_uri} parameter is
     * supported, else {@code false}.
     */
    public boolean supportsRequestURIParam() {

        return requestURIParamSupported;
    }


    /**
     * Sets the support for the {@code request_uri} authorisation request
     * parameter. Corresponds the {@code request_uri_parameter_supported}
     * metadata field.
     *
     * @param requestURIParamSupported {@code true} if the
     *                                 {@code request_uri} parameter is
     *                                 supported, else {@code false}.
     */
    public void setSupportsRequestURIParam(boolean requestURIParamSupported) {

        this.requestURIParamSupported = requestURIParamSupported;
    }


    /**
     * Gets the requirement for the {@code request_uri} parameter
     * pre-registration. Corresponds to the
     * {@code require_request_uri_registration} metadata field.
     *
     * @return {@code true} if the {@code request_uri} parameter values
     * must be pre-registered, else {@code false}.
     */
    public boolean requiresRequestURIRegistration() {

        return requireRequestURIReg;
    }


    /**
     * Sets the requirement for the {@code request_uri} parameter
     * pre-registration. Corresponds to the
     * {@code require_request_uri_registration} metadata field.
     *
     * @param requireRequestURIReg {@code true} if the {@code request_uri}
     *                             parameter values must be pre-registered,
     *                             else {@code false}.
     */
    public void setRequiresRequestURIRegistration(boolean requireRequestURIReg) {

        this.requireRequestURIReg = requireRequestURIReg;
    }


    /**
     * Gets the supported UI locales. Corresponds to the
     * {@code ui_locales_supported} metadata field.
     *
     * @return The supported UI locales, {@code null} if not specified.
     */
    public List<LangTag> getUILocales() {

        return uiLocales;
    }


    /**
     * Sets the supported UI locales. Corresponds to the
     * {@code ui_locales_supported} metadata field.
     *
     * @param uiLocales The supported UI locales, {@code null} if not
     *                  specified.
     */
    public void setUILocales(List<LangTag> uiLocales) {

        this.uiLocales = uiLocales;
    }


    /**
     * Gets the service documentation URI. Corresponds to the
     * {@code service_documentation} metadata field.
     *
     * @return The service documentation URI, {@code null} if not
     * specified.
     */
    public URI getServiceDocsURI() {

        return serviceDocsURI;
    }


    /**
     * Sets the service documentation URI. Corresponds to the
     * {@code service_documentation} metadata field.
     *
     * @param serviceDocsURI The service documentation URI, {@code null} if
     *                       not specified.
     */
    public void setServiceDocsURI(URI serviceDocsURI) {

        this.serviceDocsURI = serviceDocsURI;
    }


    /**
     * Gets the provider's policy regarding relying party use of data.
     * Corresponds to the {@code op_policy_uri} metadata field.
     *
     * @return The policy URI, {@code null} if not specified.
     */
    public URI getPolicyURI() {

        return policyURI;
    }


    /**
     * Sets the provider's policy regarding relying party use of data.
     * Corresponds to the {@code op_policy_uri} metadata field.
     *
     * @param policyURI The policy URI, {@code null} if not specified.
     */
    public void setPolicyURI(URI policyURI) {

        this.policyURI = policyURI;
    }


    /**
     * Gets the provider's terms of service. Corresponds to the
     * {@code op_tos_uri} metadata field.
     *
     * @return The terms of service URI, {@code null} if not specified.
     */
    public URI getTermsOfServiceURI() {

        return tosURI;
    }


    /**
     * Sets the provider's terms of service. Corresponds to the
     * {@code op_tos_uri} metadata field.
     *
     * @param tosURI The terms of service URI, {@code null} if not
     *               specified.
     */
    public void setTermsOfServiceURI(URI tosURI) {

        this.tosURI = tosURI;
    }


    /**
     * Gets the aliases for communication with mutual TLS. Corresponds to the
     * {@code mtls_endpoint_aliases} metadata field.
     *
     * @return The aliases for communication with mutual TLS, or {@code null}
     * when no aliases are defined.
     */
    public AuthorizationServerEndpointMetadata getMtlsEndpointAliases() {

        return mtlsEndpointAliases;
    }


    /**
     * Sets the aliases for communication with mutual TLS. Corresponds to the
     * {@code mtls_endpoint_aliases} metadata field.
     *
     * @param mtlsEndpointAliases The aliases for communication with mutual
     *                            TLS, or {@code null} when no aliases are
     *                            defined.
     */
    public void setMtlsEndpointAliases(AuthorizationServerEndpointMetadata mtlsEndpointAliases) {

        this.mtlsEndpointAliases = mtlsEndpointAliases;
    }


    /**
     * Gets the support for TLS client certificate bound access tokens.
     * Corresponds to the
     * {@code tls_client_certificate_bound_access_tokens} metadata field.
     *
     * @return {@code true} if TLS client certificate bound access tokens
     * are supported, else {@code false}.
     */
    public boolean supportsTLSClientCertificateBoundAccessTokens() {

        return tlsClientCertificateBoundAccessTokens;
    }


    /**
     * Sets the support for TLS client certificate bound access tokens.
     * Corresponds to the
     * {@code tls_client_certificate_bound_access_tokens} metadata field.
     *
     * @param tlsClientCertBoundTokens {@code true} if TLS client
     *                                 certificate bound access tokens are
     *                                 supported, else {@code false}.
     */
    public void setSupportsTLSClientCertificateBoundAccessTokens(boolean tlsClientCertBoundTokens) {

        tlsClientCertificateBoundAccessTokens = tlsClientCertBoundTokens;
    }


    /**
     * Gets the support for TLS client certificate bound access tokens.
     * Corresponds to the
     * {@code tls_client_certificate_bound_access_tokens} metadata field.
     *
     * @return {@code true} if TLS client certificate bound access tokens
     * are supported, else {@code false}.
     */
    @Deprecated
    public boolean supportsMutualTLSSenderConstrainedAccessTokens() {

        return supportsTLSClientCertificateBoundAccessTokens();
    }


    /**
     * Sets the support for TLS client certificate bound access tokens.
     * Corresponds to the
     * {@code tls_client_certificate_bound_access_tokens} metadata field.
     *
     * @param mutualTLSSenderConstrainedAccessTokens {@code true} if TLS
     *                                               client certificate
     *                                               bound access tokens
     *                                               are supported, else
     *                                               {@code false}.
     */
    @Deprecated
    public void setSupportsMutualTLSSenderConstrainedAccessTokens(boolean mutualTLSSenderConstrainedAccessTokens) {

        setSupportsTLSClientCertificateBoundAccessTokens(mutualTLSSenderConstrainedAccessTokens);
    }


    /**
     * Gets the supported JWS algorithms for JWT-encoded authorisation
     * responses. Corresponds to the
     * {@code authorization_signing_alg_values_supported} metadata field.
     *
     * @return The supported JWS algorithms, {@code null} if not specified.
     */
    public List<JWSAlgorithm> getAuthorizationJWSAlgs() {

        return authzJWSAlgs;
    }


    /**
     * Sets the supported JWS algorithms for JWT-encoded authorisation
     * responses. Corresponds to the
     * {@code authorization_signing_alg_values_supported} metadata field.
     *
     * @param authzJWSAlgs The supported JWS algorithms, {@code null} if
     *                     not specified.
     */
    public void setAuthorizationJWSAlgs(List<JWSAlgorithm> authzJWSAlgs) {

        this.authzJWSAlgs = authzJWSAlgs;
    }


    /**
     * Gets the supported JWE algorithms for JWT-encoded authorisation
     * responses. Corresponds to the
     * {@code authorization_encryption_alg_values_supported} metadata
     * field.
     *
     * @return The supported JWE algorithms, {@code null} if not specified.
     */
    public List<JWEAlgorithm> getAuthorizationJWEAlgs() {

        return authzJWEAlgs;
    }


    /**
     * Sets the supported JWE algorithms for JWT-encoded authorisation
     * responses. Corresponds to the
     * {@code authorization_encryption_alg_values_supported} metadata
     * field.
     *
     * @param authzJWEAlgs The supported JWE algorithms, {@code null} if
     *                     not specified.
     */
    public void setAuthorizationJWEAlgs(List<JWEAlgorithm> authzJWEAlgs) {

        this.authzJWEAlgs = authzJWEAlgs;
    }


    /**
     * Gets the supported encryption methods for JWT-encoded authorisation
     * responses. Corresponds to the
     * {@code authorization_encryption_enc_values_supported} metadata
     * field.
     *
     * @return The supported encryption methods, {@code null} if not
     * specified.
     */
    public List<EncryptionMethod> getAuthorizationJWEEncs() {

        return authzJWEEncs;
    }


    /**
     * Sets the supported encryption methods for JWT-encoded authorisation
     * responses. Corresponds to the
     * {@code authorization_encryption_enc_values_supported} metadata
     * field.
     *
     * @param authzJWEEncs The supported encryption methods, {@code null}
     *                     if not specified.
     */
    public void setAuthorizationJWEEncs(List<EncryptionMethod> authzJWEEncs) {

        this.authzJWEEncs = authzJWEEncs;
    }

    private void validateBuildMode() {
        if (customParametersBuilder == null) {
            throw new IllegalStateException("customParameters is in read mode and can't be changed anymore");
        }
    }

    private void ensureReadMode() {
        if (customParametersBuilder != null) {
            customParameters = customParametersBuilder.build();
            customParametersBuilder = null;
        }
    }

    /**
     * Gets the specified custom (not registered) parameter.
     *
     * @param name The parameter name. Must not be {@code null}.
     * @return The parameter value, {@code null} if not specified.
     */
    public Object getCustomParameter(String name) {
        ensureReadMode();
        return JSONObjectUtils.getJsonValueAsObject(customParameters.get(name));
    }


    /**
     * Gets the specified custom (not registered) URI parameter.
     *
     * @param name The parameter name. Must not be {@code null}.
     * @return The parameter URI value, {@code null} if not specified.
     */
    public URI getCustomURIParameter(String name) {
        ensureReadMode();
        try {
            return JSONObjectUtils.getURI(customParameters, name);
        } catch (ParseException e) {
            return null;
        }
    }


    /**
     * Sets the specified custom (not registered) parameter.
     *
     * @param name  The parameter name. Must not be {@code null}.
     * @param value The parameter value, {@code null} if not specified.
     */
    public void setCustomParameter(String name, Object value) {
        validateBuildMode();
        if (REGISTERED_PARAMETER_NAMES.contains(name)) {
            throw new IllegalArgumentException("The " + name + " parameter is registered");
        }
        JSONObjectUtils.addValue(customParametersBuilder, name, value);
    }


    /**
     * Gets the custom (not registered) parameters.
     *
     * @return The custom parameters, empty JSON object if none.
     */
    public JsonObject getCustomParameters() {
        ensureReadMode();
        return customParameters;
    }


    /**
     * Applies the OAuth 2.0 Authorisation Server metadata defaults where
     * no values have been specified.
     *
     * <ul>
     *     <li>The response modes default to {@code ["query", "fragment"]}.
     *     <li>The grant types default to {@code ["authorization_code",
     *         "implicit"]}.
     *     <li>The token endpoint authentication methods default to
     *         {@code ["client_secret_basic"]}.
     * </ul>
     */
    public void applyDefaults() {

        if (rms == null) {
            rms = new ArrayList<>(2);
            rms.add(ResponseMode.QUERY);
            rms.add(ResponseMode.FRAGMENT);
        }

        if (gts == null) {
            gts = new ArrayList<>(2);
            gts.add(GrantType.AUTHORIZATION_CODE);
            gts.add(GrantType.IMPLICIT);
        }

        if (tokenEndpointAuthMethods == null) {
            tokenEndpointAuthMethods = new ArrayList<>();
            tokenEndpointAuthMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        }
    }


    /**
     * Returns the JSON object representation of this OpenID Connect
     * provider metadata.
     *
     * @return The JSON object representation.
     */
    public JsonObjectBuilder toJSONObject() {

        JsonObjectBuilder result = super.toJSONObject();

        // Mandatory fields
        result.add("issuer", issuer.getValue());


        // Optional fields
        if (jwkSetURI != null) {
            result.add("jwks_uri", jwkSetURI.toString());
        }

        if (scope != null) {
            result.add("scopes_supported", JSONObjectUtils.asJsonArray(scope.toStringList()));
        }

        JsonArrayBuilder arrayBuilder;

        if (rts != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (ResponseType rt : rts) {
                arrayBuilder.add(rt.toString());
            }

            result.add("response_types_supported", arrayBuilder.build());
        }

        if (rms != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (ResponseMode rm : rms) {
                arrayBuilder.add(rm.getValue());
            }
            result.add("response_modes_supported", arrayBuilder);
        }

        if (gts != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (GrantType gt : gts) {
                arrayBuilder.add(gt.toString());
            }
            result.add("grant_types_supported", arrayBuilder);
        }

        if (codeChallengeMethods != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (CodeChallengeMethod m : codeChallengeMethods) {
                arrayBuilder.add(m.getValue());
            }
            result.add("code_challenge_methods_supported", arrayBuilder);
        }


        if (tokenEndpointAuthMethods != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (ClientAuthenticationMethod m : tokenEndpointAuthMethods) {
                arrayBuilder.add(m.getValue());
            }
            result.add("token_endpoint_auth_methods_supported", arrayBuilder);
        }

        if (tokenEndpointJWSAlgs != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (JWSAlgorithm alg : tokenEndpointJWSAlgs) {
                arrayBuilder.add(alg.getName());
            }
            result.add("token_endpoint_auth_signing_alg_values_supported", arrayBuilder);
        }

        if (introspectionEndpointAuthMethods != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (ClientAuthenticationMethod m : introspectionEndpointAuthMethods) {
                arrayBuilder.add(m.getValue());
            }
            result.add("introspection_endpoint_auth_methods_supported", arrayBuilder);
        }

        if (introspectionEndpointJWSAlgs != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (JWSAlgorithm alg : introspectionEndpointJWSAlgs) {
                arrayBuilder.add(alg.getName());
            }
            result.add("introspection_endpoint_auth_signing_alg_values_supported", arrayBuilder);
        }

        if (revocationEndpointAuthMethods != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (ClientAuthenticationMethod m : revocationEndpointAuthMethods) {
                arrayBuilder.add(m.getValue());
            }
            result.add("revocation_endpoint_auth_methods_supported", arrayBuilder);
        }

        if (revocationEndpointJWSAlgs != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (JWSAlgorithm alg : revocationEndpointJWSAlgs) {
                arrayBuilder.add(alg.getName());
            }
            result.add("revocation_endpoint_auth_signing_alg_values_supported", arrayBuilder);
        }

        if (requestObjectJWSAlgs != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (JWSAlgorithm alg : requestObjectJWSAlgs) {
                arrayBuilder.add(alg.getName());
            }
            result.add("request_object_signing_alg_values_supported", arrayBuilder);
        }

        if (requestObjectJWEAlgs != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (JWEAlgorithm alg : requestObjectJWEAlgs) {
                arrayBuilder.add(alg.getName());
            }
            result.add("request_object_encryption_alg_values_supported", arrayBuilder);
        }

        if (requestObjectJWEEncs != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (EncryptionMethod m : requestObjectJWEEncs) {
                arrayBuilder.add(m.getName());
            }
            result.add("request_object_encryption_enc_values_supported", arrayBuilder);
        }

        if (uiLocales != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (LangTag l : uiLocales) {
                arrayBuilder.add(l.toString());
            }
            result.add("ui_locales_supported", arrayBuilder);
        }

        if (serviceDocsURI != null) {
            result.add("service_documentation", serviceDocsURI.toString());
        }
        if (policyURI != null) {
            result.add("op_policy_uri", policyURI.toString());
        }
        if (tosURI != null) {
            result.add("op_tos_uri", tosURI.toString());
        }
        result.add("request_parameter_supported", requestParamSupported);
        result.add("request_uri_parameter_supported", requestURIParamSupported);
        result.add("require_request_uri_registration", requireRequestURIReg);

        if (mtlsEndpointAliases != null) {
            result.add("mtls_endpoint_aliases", mtlsEndpointAliases.toJSONObject());
        }
        result.add("tls_client_certificate_bound_access_tokens", tlsClientCertificateBoundAccessTokens);

        // JARM
        if (authzJWSAlgs != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (JWSAlgorithm alg : authzJWSAlgs) {
                arrayBuilder.add(alg.getName());
            }
            result.add("authorization_signing_alg_values_supported", arrayBuilder);
        }

        if (authzJWEAlgs != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (JWEAlgorithm alg : authzJWEAlgs) {
                arrayBuilder.add(alg.getName());
            }
            result.add("authorization_encryption_alg_values_supported", arrayBuilder);
        }

        if (authzJWEEncs != null) {

            arrayBuilder = Json.createArrayBuilder();

            for (EncryptionMethod m : authzJWEEncs) {
                arrayBuilder.add(m.getName());
            }
            result.add("authorization_encryption_enc_values_supported", arrayBuilder);
        }

        // Append any custom (not registered) parameters
        ensureReadMode();
        for (Map.Entry<String, JsonValue> entry : customParameters.entrySet()) {
            if (entry.getValue().getValueType() == JsonValue.ValueType.NULL) {
                result.addNull(entry.getKey());
            } else {
                result.add(entry.getKey(), entry.getValue());
            }
        }

        return result;
    }


    /**
     * Parses an OAuth 2.0 Authorisation Server metadata from the specified
     * JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The OAuth 2.0 Authorisation Server metadata.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to an
     *                                  OAuth 2.0 Authorisation Server metadata.
     */
    public static AuthorizationServerMetadata parse(JsonObject jsonObject)
            throws OAuth2JSONParseException {

        // Parse issuer and subject_types_supported first

        Issuer issuer;
        try {
            issuer = new Issuer(JSONObjectUtils.getURIRequired(jsonObject, "issuer").toString());
        } catch (ParseException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }

        AuthorizationServerEndpointMetadata asEndpoints = AuthorizationServerEndpointMetadata.parse(jsonObject);

        AuthorizationServerMetadata as;

        try {
            as = new AuthorizationServerMetadata(issuer); // validates issuer syntax
        } catch (IllegalArgumentException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }

        // Endpoints
        as.setAuthorizationEndpointURI(asEndpoints.getAuthorizationEndpointURI());
        as.setTokenEndpointURI(asEndpoints.getTokenEndpointURI());
        as.setRegistrationEndpointURI(asEndpoints.getRegistrationEndpointURI());
        as.setIntrospectionEndpointURI(asEndpoints.getIntrospectionEndpointURI());
        as.setRevocationEndpointURI(asEndpoints.getRevocationEndpointURI());
        as.setDeviceAuthorizationEndpointURI(asEndpoints.getDeviceAuthorizationEndpointURI());
        as.setRequestObjectEndpoint(asEndpoints.getRequestObjectEndpoint());
        as.setPushedAuthorizationRequestEndpoint(asEndpoints.getPushedAuthorizationRequestEndpoint());
        try {
            as.jwkSetURI = JSONObjectUtils.getURI(jsonObject, "jwks_uri");
        } catch (ParseException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }

        // AS capabilities
        if (jsonObject.get("scopes_supported") != null) {

            as.scope = new Scope();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "scopes_supported")) {

                if (v != null) {
                    as.scope.add(new Scope.Value(v));
                }
            }
        }

        if (jsonObject.get("response_types_supported") != null) {

            as.rts = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "response_types_supported")) {

                if (v != null) {
                    as.rts.add(ResponseType.parse(v));
                }
            }
        }

        if (jsonObject.get("response_modes_supported") != null) {

            as.rms = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "response_modes_supported")) {

                if (v != null) {
                    as.rms.add(new ResponseMode(v));
                }
            }
        }

        if (jsonObject.get("grant_types_supported") != null) {

            as.gts = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "grant_types_supported")) {

                if (v != null) {
                    as.gts.add(GrantType.parse(v));
                }
            }
        }

        if (jsonObject.get("code_challenge_methods_supported") != null) {

            as.codeChallengeMethods = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "code_challenge_methods_supported")) {

                if (v != null) {
                    as.codeChallengeMethods.add(CodeChallengeMethod.parse(v));
                }
            }
        }

        if (jsonObject.get("token_endpoint_auth_methods_supported") != null) {

            as.tokenEndpointAuthMethods = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "token_endpoint_auth_methods_supported")) {

                if (v != null) {
                    as.tokenEndpointAuthMethods.add(ClientAuthenticationMethod.parse(v));
                }
            }
        }

        if (jsonObject.get("token_endpoint_auth_signing_alg_values_supported") != null) {

            as.tokenEndpointJWSAlgs = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "token_endpoint_auth_signing_alg_values_supported")) {

                if (v != null && v.equals(Algorithm.NONE.getName())) {
                    throw new OAuth2JSONParseException("The none algorithm is not accepted");
                }

                if (v != null) {
                    as.tokenEndpointJWSAlgs.add(JWSAlgorithm.parse(v));
                }
            }
        }

        if (jsonObject.get("introspection_endpoint_auth_methods_supported") != null) {

            as.introspectionEndpointAuthMethods = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "introspection_endpoint_auth_methods_supported")) {

                if (v != null) {
                    as.introspectionEndpointAuthMethods.add(ClientAuthenticationMethod.parse(v));
                }
            }
        }

        if (jsonObject.get("introspection_endpoint_auth_signing_alg_values_supported") != null) {

            as.introspectionEndpointJWSAlgs = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "introspection_endpoint_auth_signing_alg_values_supported")) {

                if (v != null && v.equals(Algorithm.NONE.getName())) {
                    throw new OAuth2JSONParseException("The none algorithm is not accepted");
                }

                if (v != null) {
                    as.introspectionEndpointJWSAlgs.add(JWSAlgorithm.parse(v));
                }
            }
        }

        if (jsonObject.get("revocation_endpoint_auth_methods_supported") != null) {

            as.revocationEndpointAuthMethods = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "revocation_endpoint_auth_methods_supported")) {

                if (v != null) {
                    as.revocationEndpointAuthMethods.add(ClientAuthenticationMethod.parse(v));
                }
            }
        }

        if (jsonObject.get("revocation_endpoint_auth_signing_alg_values_supported") != null) {

            as.revocationEndpointJWSAlgs = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "revocation_endpoint_auth_signing_alg_values_supported")) {

                if (v != null && v.equals(Algorithm.NONE.getName())) {
                    throw new OAuth2JSONParseException("The none algorithm is not accepted");
                }

                if (v != null) {
                    as.revocationEndpointJWSAlgs.add(JWSAlgorithm.parse(v));
                }
            }
        }


        // Request object
        if (jsonObject.get("request_object_signing_alg_values_supported") != null) {

            as.requestObjectJWSAlgs = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "request_object_signing_alg_values_supported")) {

                if (v != null) {
                    as.requestObjectJWSAlgs.add(JWSAlgorithm.parse(v));
                }
            }
        }


        if (jsonObject.get("request_object_encryption_alg_values_supported") != null) {

            as.requestObjectJWEAlgs = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "request_object_encryption_alg_values_supported")) {

                if (v != null) {
                    as.requestObjectJWEAlgs.add(JWEAlgorithm.parse(v));
                }
            }
        }


        if (jsonObject.get("request_object_encryption_enc_values_supported") != null) {

            as.requestObjectJWEEncs = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "request_object_encryption_enc_values_supported")) {

                if (v != null) {
                    as.requestObjectJWEEncs.add(EncryptionMethod.parse(v));
                }
            }
        }


        // Misc

        if (jsonObject.get("ui_locales_supported") != null) {

            as.uiLocales = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "ui_locales_supported")) {

                if (v != null) {

                    try {
                        as.uiLocales.add(LangTag.parse(v));

                    } catch (LangTagException e) {

                        throw new OAuth2JSONParseException("Invalid ui_locales_supported field: " + e.getMessage(), e);
                    }
                }
            }
        }

        try {
            if (jsonObject.get("service_documentation") != null) {
                as.serviceDocsURI = JSONObjectUtils.getURI(jsonObject, "service_documentation");
            }

            if (jsonObject.get("op_policy_uri") != null) {
                as.policyURI = JSONObjectUtils.getURI(jsonObject, "op_policy_uri");
            }

            if (jsonObject.get("op_tos_uri") != null) {
                as.tosURI = JSONObjectUtils.getURI(jsonObject, "op_tos_uri");
            }

        } catch (ParseException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
        if (jsonObject.get("request_parameter_supported") != null) {
            as.requestParamSupported = jsonObject.getBoolean("request_parameter_supported");
        }

        if (jsonObject.get("request_uri_parameter_supported") != null) {
            as.requestURIParamSupported = jsonObject.getBoolean("request_uri_parameter_supported");
        }

        if (jsonObject.get("require_request_uri_registration") != null) {
            as.requireRequestURIReg = jsonObject.getBoolean("require_request_uri_registration");
        }

        if (jsonObject.get("mtls_endpoint_aliases") != null) {
            as.mtlsEndpointAliases = AuthorizationServerEndpointMetadata.parse(jsonObject.getJsonObject("mtls_endpoint_aliases"));
        }

        if (JSONObjectUtils.hasValue(jsonObject, "tls_client_certificate_bound_access_tokens")) {
            as.tlsClientCertificateBoundAccessTokens = jsonObject.getBoolean("tls_client_certificate_bound_access_tokens");
        }

        // JARM
        if (jsonObject.get("authorization_signing_alg_values_supported") != null) {

            as.authzJWSAlgs = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "authorization_signing_alg_values_supported")) {

                if (v != null) {
                    as.authzJWSAlgs.add(JWSAlgorithm.parse(v));
                }
            }
        }


        if (jsonObject.get("authorization_encryption_alg_values_supported") != null) {

            as.authzJWEAlgs = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "authorization_encryption_alg_values_supported")) {

                if (v != null) {
                    as.authzJWEAlgs.add(JWEAlgorithm.parse(v));
                }
            }
        }


        if (jsonObject.get("authorization_encryption_enc_values_supported") != null) {

            as.authzJWEEncs = new ArrayList<>();

            for (String v : JSONObjectUtils.getStringList(jsonObject, "authorization_encryption_enc_values_supported")) {

                if (v != null) {
                    as.authzJWEEncs.add(EncryptionMethod.parse(v));
                }
            }
        }


        // Parse custom (not registered) parameters
        Set<String> allKeys = new HashSet<>(jsonObject.keySet());

        allKeys.removeAll(REGISTERED_PARAMETER_NAMES);
        for (String key : allKeys) {

            as.setCustomParameter(key, JSONObjectUtils.getJsonValueAsObject(jsonObject.get(key)));
        }


        return as;
    }


    /**
     * Parses an OAuth 2.0 Authorisation Server metadata from the specified
     * JSON object string.
     *
     * @param s The JSON object sting to parse. Must not be {@code null}.
     * @return The OAuth 2.0 Authorisation Server metadata.
     * @throws ParseException If the JSON object string couldn't be parsed
     *                        to an OAuth 2.0 Authorisation Server
     *                        metadata.
     */
    public static AuthorizationServerMetadata parse(String s)
            throws OAuth2JSONParseException {

        try {
            return parse(JSONObjectUtils.parse(s));
        } catch (ParseException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
    }


    /**
     * Resolves OAuth 2.0 authorisation server metadata URL from the
     * specified issuer identifier.
     *
     * @param issuer The issuer identifier. Must represent a valid HTTPS or
     *               HTTP URL. Must not be {@code null}.
     * @return The OAuth 2.0 authorisation server metadata URL.
     * @throws GeneralException If the issuer identifier is invalid.
     */
    public static URL resolveURL(Issuer issuer)
            throws GeneralException {

        try {
            URL issuerURL = new URL(issuer.getValue());

            // Validate but don't insist on HTTPS
            if (issuerURL.getQuery() != null && !issuerURL.getQuery().trim().isEmpty()) {
                throw new GeneralException("The issuer identifier must not contain a query component");
            }

            if (issuerURL.getPath() != null && issuerURL.getPath().endsWith("/")) {
                return new URL(issuerURL + ".well-known/oauth-authorization-server");
            } else {
                return new URL(issuerURL + "/.well-known/oauth-authorization-server");
            }

        } catch (MalformedURLException e) {
            throw new GeneralException("The issuer identifier doesn't represent a valid URL: " + e.getMessage(), e);
        }
    }


    /**
     * Resolves OAuth 2.0 authorisation server metadata from the specified
     * issuer identifier. The metadata is downloaded by HTTP GET from
     * {@code [issuer-url]/.well-known/oauth-authorization-server}.
     *
     * @param issuer The issuer identifier. Must represent a valid HTTPS or
     *               HTTP URL. Must not be {@code null}.
     * @return The OAuth 2.0 authorisation server metadata.
     * @throws GeneralException If the issuer identifier or the downloaded
     *                          metadata are invalid.
     * @throws IOException      On a HTTP exception.
     */
    public static AuthorizationServerMetadata resolve(Issuer issuer)
            throws GeneralException, IOException {

        return resolve(issuer, 0, 0);
    }


    /**
     * Resolves OAuth 2.0 authorisation server metadata from the specified
     * issuer identifier. The metadata is downloaded by HTTP GET from
     * {@code [issuer-url]/.well-known/oauth-authorization-server}.
     *
     * @param issuer         The issuer identifier. Must represent a valid
     *                       HTTPS or HTTP URL. Must not be {@code null}.
     * @param connectTimeout The HTTP connect timeout, in milliseconds.
     *                       Zero implies no timeout. Must not be negative.
     * @param readTimeout    The HTTP response read timeout, in
     *                       milliseconds. Zero implies no timeout. Must
     *                       not be negative.
     * @return The OAuth 2.0 authorisation server metadata.
     * @throws GeneralException If the issuer identifier or the downloaded
     *                          metadata are invalid.
     * @throws IOException      On a HTTP exception.
     */
    public static AuthorizationServerMetadata resolve(Issuer issuer,
                                                      int connectTimeout,
                                                      int readTimeout)
            throws GeneralException, IOException {

        URL configURL = resolveURL(issuer);

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, configURL);
        httpRequest.setConnectTimeout(connectTimeout);
        httpRequest.setReadTimeout(readTimeout);

        HTTPResponse httpResponse = httpRequest.send();

        if (httpResponse.getStatusCode() != 200) {
            throw new IOException("Couldn't download OAuth 2.0 Authorization Server metadata from " + configURL +
                    ": Status code " + httpResponse.getStatusCode());
        }

        JsonObject jsonObject = httpResponse.getContentAsJSONObject();

        AuthorizationServerMetadata as = AuthorizationServerMetadata.parse(jsonObject);

        if (!issuer.equals(as.issuer)) {
            throw new GeneralException("The returned issuer doesn't match the expected: " + as.getIssuer());
        }

        return as;
    }
}
