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
package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.langtag.LangTag;
import be.atbash.ee.langtag.LangTagUtils;
import be.atbash.ee.oauth2.sdk.GrantType;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.id.SoftwareID;
import be.atbash.ee.oauth2.sdk.id.SoftwareVersion;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.*;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.*;


/**
 * Client metadata.
 *
 * <p>Example client metadata, serialised to a JSON object:
 *
 * <pre>
 * {
 *  "redirect_uris"              : ["https://client.example.org/callback",
 *                                  "https://client.example.org/callback2"],
 *  "client_name"                : "My Example Client",
 *  "client_name#ja-Jpan-JP"     : "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
 *  "token_endpoint_auth_method" : "client_secret_basic",
 *  "scope"                      : "read write dolphin",
 *  "logo_uri"                   : "https://client.example.org/logo.png",
 *  "jwks_uri"                   : "https://client.example.org/my_public_keys.jwks"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         2.
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (draft-ietf-oauth-mtls-15), sections 2.1.2 and 3.4.
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM).
 * </ul>
 */
public class ClientMetadata {


    /**
     * The registered parameter names.
     */
    private static final Set<String> REGISTERED_PARAMETER_NAMES;


    static {
        Set<String> p = new HashSet<>();

        p.add("redirect_uris");
        p.add("scope");
        p.add("response_types");
        p.add("grant_types");
        p.add("contacts");
        p.add("client_name");
        p.add("logo_uri");
        p.add("client_uri");
        p.add("policy_uri");
        p.add("tos_uri");
        p.add("token_endpoint_auth_method");
        p.add("token_endpoint_auth_signing_alg");
        p.add("jwks_uri");
        p.add("jwks");
        p.add("request_uris");
        p.add("request_object_signing_alg");
        p.add("request_object_encryption_alg");
        p.add("request_object_encryption_enc");
        p.add("software_id");
        p.add("software_version");
        p.add("tls_client_certificate_bound_access_tokens");
        p.add("tls_client_auth_subject_dn");
        p.add("tls_client_auth_san_dns");
        p.add("tls_client_auth_san_uri");
        p.add("tls_client_auth_san_ip");
        p.add("tls_client_auth_san_email");
        p.add("authorization_signed_response_alg");
        p.add("authorization_encrypted_response_alg");
        p.add("authorization_encrypted_response_enc");

        REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
    }


    /**
     * Redirect URIs.
     */
    private Set<URI> redirectURIs;


    /**
     * The client OAuth 2.0 scope.
     */
    private Scope scope;


    /**
     * The expected OAuth 2.0 response types.
     */
    private Set<ResponseType> responseTypes;


    /**
     * The expected OAuth 2.0 grant types.
     */
    private Set<GrantType> grantTypes;


    /**
     * Administrator email contacts for the client.
     */
    private List<String> contacts;


    /**
     * The client name.
     */
    private final Map<LangTag, String> nameEntries;


    /**
     * The client application logo.
     */
    private final Map<LangTag, URI> logoURIEntries;


    /**
     * The client URI entries.
     */
    private final Map<LangTag, URI> uriEntries;


    /**
     * The client policy for use of end-user data.
     */
    private Map<LangTag, URI> policyURIEntries;


    /**
     * The client terms of service.
     */
    private final Map<LangTag, URI> tosURIEntries;


    /**
     * Token endpoint authentication method.
     */
    private ClientAuthenticationMethod authMethod;


    /**
     * The JSON Web Signature (JWS) algorithm required for
     * {@code private_key_jwt} and {@code client_secret_jwt}
     * authentication at the Token endpoint.
     */
    private JWSAlgorithm authJWSAlg;


    /**
     * URI for this client's JSON Web Key (JWK) set containing key(s) that
     * are used in signing requests to the server and key(s) for encrypting
     * responses.
     */
    private URI jwkSetURI;


    /**
     * Client's JSON Web Key (JWK) set containing key(s) that are used in
     * signing requests to the server and key(s) for encrypting responses.
     * Intended as an alternative to {@link #jwkSetURI} for native clients.
     */
    private JWKSet jwkSet;


    /**
     * Pre-registered request object URIs.
     */
    private Set<URI> requestObjectURIs;


    /**
     * The JSON Web Signature (JWS) algorithm required for request objects
     * sent by this client.
     */
    private JWSAlgorithm requestObjectJWSAlg;


    /**
     * The JSON Web Encryption (JWE) algorithm required for request objects
     * sent by this client.
     */
    private JWEAlgorithm requestObjectJWEAlg;


    /**
     * The JSON Web Encryption (JWE) method required for request objects
     * sent by this client.
     */
    private EncryptionMethod requestObjectJWEEnc;


    /**
     * Identifier for the OAuth 2.0 client software.
     */
    private SoftwareID softwareID;


    /**
     * Version identifier for the OAuth 2.0 client software.
     */
    private SoftwareVersion softwareVersion;


    /**
     * Preference for TLS client certificate bound access tokens.
     */
    private boolean tlsClientCertificateBoundAccessTokens = false;


    /**
     * The expected subject distinguished name (DN) of the client X.509
     * certificate the in mutual TLS authentication.
     */
    private String tlsClientAuthSubjectDN = null;


    /**
     * The expected dNSName SAN entry in the X.509 certificate, which
     * the OAuth client will use in mutual TLS authentication.
     */
    private String tlsClientAuthSanDNS = null;


    /**
     * The expected uniformResourceIdentifier SAN entry in the X.509
     * certificate, which the OAuth client will use in mutual TLS
     * authentication.
     */
    private String tlsClientAuthSanURI = null;


    /**
     * The expected iPAddress SAN entry in the X.509 certificate, which
     * the OAuth client will use in mutual TLS authentication.
     */
    private String tlsClientAuthSanIP = null;


    /**
     * The expected rfc822Name SAN entry in the X.509 certificate, which
     * the OAuth client will use in mutual TLS authentication.
     */
    private String tlsClientAuthSanEmail = null;


    /**
     * The JWS algorithm for JWT-encoded authorisation responses.
     */
    private JWSAlgorithm authzJWSAlg;


    /**
     * The JWE algorithm for JWT-encoded authorisation responses.
     */
    private JWEAlgorithm authzJWEAlg;


    /**
     * The encryption method for JWT-encoded authorisation responses.
     */
    private EncryptionMethod authzJWEEnc;


    /**
     * The custom metadata fields.
     */
    private JsonObject customFields;


    /**
     * Creates a new OAuth 2.0 client metadata instance.
     */
    public ClientMetadata() {

        nameEntries = new HashMap<>();
        logoURIEntries = new HashMap<>();
        uriEntries = new HashMap<>();
        policyURIEntries = new HashMap<>();
        policyURIEntries = new HashMap<>();
        tosURIEntries = new HashMap<>();
        customFields = Json.createObjectBuilder().build();
    }


    /**
     * Creates a shallow copy of the specified OAuth 2.0 client metadata
     * instance.
     *
     * @param metadata The client metadata to copy. Must not be
     *                 {@code null}.
     */
    public ClientMetadata(final ClientMetadata metadata) {

        redirectURIs = metadata.redirectURIs;
        scope = metadata.scope;
        responseTypes = metadata.responseTypes;
        grantTypes = metadata.grantTypes;
        contacts = metadata.contacts;
        nameEntries = metadata.nameEntries;
        logoURIEntries = metadata.logoURIEntries;
        uriEntries = metadata.uriEntries;
        policyURIEntries = metadata.policyURIEntries;
        tosURIEntries = metadata.tosURIEntries;
        authMethod = metadata.authMethod;
        authJWSAlg = metadata.authJWSAlg;
        jwkSetURI = metadata.jwkSetURI;
        jwkSet = metadata.getJWKSet();
        requestObjectURIs = metadata.requestObjectURIs;
        requestObjectJWSAlg = metadata.requestObjectJWSAlg;
        requestObjectJWEAlg = metadata.requestObjectJWEAlg;
        requestObjectJWEEnc = metadata.requestObjectJWEEnc;
        softwareID = metadata.softwareID;
        softwareVersion = metadata.softwareVersion;
        tlsClientCertificateBoundAccessTokens = metadata.tlsClientCertificateBoundAccessTokens;
        tlsClientAuthSubjectDN = metadata.tlsClientAuthSubjectDN;
        tlsClientAuthSanDNS = metadata.tlsClientAuthSanDNS;
        tlsClientAuthSanURI = metadata.tlsClientAuthSanURI;
        tlsClientAuthSanIP = metadata.tlsClientAuthSanIP;
        tlsClientAuthSanEmail = metadata.tlsClientAuthSanEmail;
        authzJWSAlg = metadata.authzJWSAlg;
        authzJWEAlg = metadata.authzJWEAlg;
        authzJWEEnc = metadata.authzJWEEnc;
        customFields = metadata.customFields;
    }


    /**
     * Gets the registered (standard) OAuth 2.0 client metadata parameter
     * names.
     *
     * @return The registered parameter names, as an unmodifiable set.
     */
    public static Set<String> getRegisteredParameterNames() {

        return REGISTERED_PARAMETER_NAMES;
    }


    /**
     * Gets the redirection URIs for this client. Corresponds to the
     * {@code redirect_uris} client metadata field.
     *
     * @return The redirection URIs, {@code null} if not specified.
     */
    public Set<URI> getRedirectionURIs() {

        return redirectURIs;
    }


    /**
     * Gets one of the redirection URIs for this client. Corresponds to the
     * {@code redirect_uris} client metadata field.
     *
     * @return The redirection URI, {@code null} if not specified.
     */
    public URI getRedirectionURI() {

        if (redirectURIs != null && !redirectURIs.isEmpty()) {
            return redirectURIs.iterator().next();
        } else {
            return null;
        }
    }


    /**
     * Gets the redirection URIs for this client as strings. Corresponds to
     * the {@code redirect_uris} client metadata field.
     *
     * <p>This short-hand method is intended to enable string-based URI
     * comparison.
     *
     * @return The redirection URIs as strings, {@code null} if not
     * specified.
     */
    public Set<String> getRedirectionURIStrings() {

        if (redirectURIs == null) {
            return null;
        }

        Set<String> uriStrings = new HashSet<>();

        for (URI uri : redirectURIs) {
            uriStrings.add(uri.toString());
        }

        return uriStrings;
    }


    /**
     * Sets the redirection URIs for this client. Corresponds to the
     * {@code redirect_uris} client metadata field.
     *
     * @param redirectURIs The redirection URIs, {@code null} if not
     *                     specified. Valid redirection URIs must not
     *                     contain a fragment.
     */
    public void setRedirectionURIs(final Set<URI> redirectURIs) {

        if (redirectURIs != null) {
            // check URIs
            for (URI uri : redirectURIs) {
                if (uri == null) {
                    throw new IllegalArgumentException("The redirect_uri must not be null");
                }
                if (uri.getFragment() != null) {
                    throw new IllegalArgumentException("The redirect_uri must not contain fragment");
                }
            }
            this.redirectURIs = redirectURIs;
        } else {
            this.redirectURIs = null;
        }
    }


    /**
     * Sets a single redirection URI for this client. Corresponds to the
     * {@code redirect_uris} client metadata field.
     *
     * @param redirectURI The redirection URIs, {@code null} if not
     *                    specified. A valid redirection URI must not
     *                    contain a fragment.
     */
    public void setRedirectionURI(final URI redirectURI) {

        setRedirectionURIs(redirectURI != null ? Collections.singleton(redirectURI) : null);
    }


    /**
     * Gets the scope values that the client can use when requesting access
     * tokens. Corresponds to the {@code scope} client metadata field.
     *
     * @return The scope, {@code null} if not specified.
     */
    public Scope getScope() {

        return scope;
    }


    /**
     * Checks if the scope matadata field is set and contains the specified
     * scope value.
     *
     * @param scopeValue The scope value. Must not be {@code null}.
     * @return {@code true} if the scope value is contained, else
     * {@code false}.
     */
    public boolean hasScopeValue(final Scope.Value scopeValue) {

        return scope != null && scope.contains(scopeValue);
    }


    /**
     * Sets the scope values that the client can use when requesting access
     * tokens. Corresponds to the {@code scope} client metadata field.
     *
     * @param scope The scope, {@code null} if not specified.
     */
    public void setScope(final Scope scope) {

        this.scope = scope;
    }


    /**
     * Gets the expected OAuth 2.0 response types. Corresponds to the
     * {@code response_types} client metadata field.
     *
     * @return The response types, {@code null} if not specified.
     */
    public Set<ResponseType> getResponseTypes() {

        return responseTypes;
    }


    /**
     * Sets the expected OAuth 2.0 response types. Corresponds to the
     * {@code response_types} client metadata field.
     *
     * @param responseTypes The response types, {@code null} if not
     *                      specified.
     */
    public void setResponseTypes(final Set<ResponseType> responseTypes) {

        this.responseTypes = responseTypes;
    }


    /**
     * Gets the expected OAuth 2.0 grant types. Corresponds to the
     * {@code grant_types} client metadata field.
     *
     * @return The grant types, {@code null} if not specified.
     */
    public Set<GrantType> getGrantTypes() {

        return grantTypes;
    }


    /**
     * Sets the expected OAuth 2.0 grant types. Corresponds to the
     * {@code grant_types} client metadata field.
     *
     * @param grantTypes The grant types, {@code null} if not specified.
     */
    public void setGrantTypes(final Set<GrantType> grantTypes) {

        this.grantTypes = grantTypes;
    }


    /**
     * Gets the administrator email contacts for the client. Corresponds to
     * the {@code contacts} client metadata field.
     *
     * <p>Use {@link #getEmailContacts()} instead.
     *
     * @return The administrator email contacts, {@code null} if not
     * specified.
     */
    @Deprecated
    public List<InternetAddress> getContacts() {

        if (contacts == null) {
            return null;
        }

        List<InternetAddress> addresses = new LinkedList<>();
        for (String s : contacts) {
            if (s == null) {
                continue;
            }
            try {
                addresses.add(new InternetAddress(s, false));
            } catch (AddressException e) {
                // ignore
            }
        }
        return addresses;
    }


    /**
     * Sets the administrator email contacts for the client. Corresponds to
     * the {@code contacts} client metadata field.
     *
     * <p>Use {@link #setEmailContacts(List)} instead.
     *
     * @param contacts The administrator email contacts, {@code null} if
     *                 not specified.
     */
    @Deprecated
    public void setContacts(final List<InternetAddress> contacts) {

        if (contacts == null) {
            this.contacts = null;
            return;
        }

        List<String> addresses = new LinkedList<>();
        for (InternetAddress a : contacts) {
            if (a != null) {
                addresses.add(a.toString());
            }
        }
        this.contacts = addresses;
    }


    /**
     * Gets the administrator email contacts for the client. Corresponds to
     * the {@code contacts} client metadata field.
     *
     * @return The administrator email contacts, {@code null} if not
     * specified.
     */
    public List<String> getEmailContacts() {

        return contacts;
    }


    /**
     * Sets the administrator email contacts for the client. Corresponds to
     * the {@code contacts} client metadata field.
     *
     * @param contacts The administrator email contacts, {@code null} if
     *                 not specified.
     */
    public void setEmailContacts(final List<String> contacts) {

        this.contacts = contacts;
    }


    /**
     * Gets the client name. Corresponds to the {@code client_name} client
     * metadata field, with no language tag.
     *
     * @return The client name, {@code null} if not specified.
     */
    public String getName() {

        return getName(null);
    }


    /**
     * Gets the client name. Corresponds to the {@code client_name} client
     * metadata field, with an optional language tag.
     *
     * @param langTag The language tag of the entry, {@code null} to get
     *                the non-tagged entry.
     * @return The client name, {@code null} if not specified.
     */
    public String getName(final LangTag langTag) {

        return nameEntries.get(langTag);
    }


    /**
     * Gets the client name entries. Corresponds to the {@code client_name}
     * client metadata field.
     *
     * @return The client name entries, empty map if none.
     */
    public Map<LangTag, String> getNameEntries() {

        return nameEntries;
    }


    /**
     * Sets the client name. Corresponds to the {@code client_name} client
     * metadata field, with no language tag.
     *
     * @param name The client name, {@code null} if not specified.
     */
    public void setName(final String name) {

        nameEntries.put(null, name);
    }


    /**
     * Sets the client name. Corresponds to the {@code client_name} client
     * metadata field, with an optional language tag.
     *
     * @param name    The client name. Must not be {@code null}.
     * @param langTag The language tag, {@code null} if not specified.
     */
    public void setName(final String name, final LangTag langTag) {

        nameEntries.put(langTag, name);
    }


    /**
     * Gets the client application logo. Corresponds to the
     * {@code logo_uri} client metadata field, with no language
     * tag.
     *
     * @return The logo URI, {@code null} if not specified.
     */
    public URI getLogoURI() {

        return getLogoURI(null);
    }


    /**
     * Gets the client application logo. Corresponds to the
     * {@code logo_uri} client metadata field, with an optional
     * language tag.
     *
     * @param langTag The language tag, {@code null} if not specified.
     * @return The logo URI, {@code null} if not specified.
     */
    public URI getLogoURI(final LangTag langTag) {

        return logoURIEntries.get(langTag);
    }


    /**
     * Gets the client application logo entries. Corresponds to the
     * {@code logo_uri} client metadata field.
     *
     * @return The logo URI entries, empty map if none.
     */
    public Map<LangTag, URI> getLogoURIEntries() {

        return logoURIEntries;
    }


    /**
     * Sets the client application logo. Corresponds to the
     * {@code logo_uri} client metadata field, with no language
     * tag.
     *
     * @param logoURI The logo URI, {@code null} if not specified.
     */
    public void setLogoURI(final URI logoURI) {

        logoURIEntries.put(null, logoURI);
    }


    /**
     * Sets the client application logo. Corresponds to the
     * {@code logo_uri} client metadata field, with an optional
     * language tag.
     *
     * @param logoURI The logo URI. Must not be {@code null}.
     * @param langTag The language tag, {@code null} if not specified.
     */
    public void setLogoURI(final URI logoURI, final LangTag langTag) {

        logoURIEntries.put(langTag, logoURI);
    }


    /**
     * Gets the client home page. Corresponds to the {@code client_uri}
     * client metadata field, with no language tag.
     *
     * @return The client URI, {@code null} if not specified.
     */
    public URI getURI() {

        return getURI(null);
    }


    /**
     * Gets the client home page. Corresponds to the {@code client_uri}
     * client metadata field, with an optional language tag.
     *
     * @param langTag The language tag, {@code null} if not specified.
     * @return The client URI, {@code null} if not specified.
     */
    public URI getURI(final LangTag langTag) {

        return uriEntries.get(langTag);
    }


    /**
     * Gets the client home page entries. Corresponds to the
     * {@code client_uri} client metadata field.
     *
     * @return The client URI entries, empty map if none.
     */
    public Map<LangTag, URI> getURIEntries() {

        return uriEntries;
    }


    /**
     * Sets the client home page. Corresponds to the {@code client_uri}
     * client metadata field, with no language tag.
     *
     * @param uri The client URI, {@code null} if not specified.
     */
    public void setURI(final URI uri) {

        uriEntries.put(null, uri);
    }


    /**
     * Sets the client home page. Corresponds to the {@code client_uri}
     * client metadata field, with an optional language tag.
     *
     * @param uri     The URI. Must not be {@code null}.
     * @param langTag The language tag, {@code null} if not specified.
     */
    public void setURI(final URI uri, final LangTag langTag) {

        uriEntries.put(langTag, uri);
    }


    /**
     * Gets the client policy for use of end-user data. Corresponds to the
     * {@code policy_uri} client metadata field, with no language
     * tag.
     *
     * @return The policy URI, {@code null} if not specified.
     */
    public URI getPolicyURI() {

        return getPolicyURI(null);
    }


    /**
     * Gets the client policy for use of end-user data. Corresponds to the
     * {@code policy_uri} client metadata field, with an optional
     * language tag.
     *
     * @param langTag The language tag, {@code null} if not specified.
     * @return The policy URI, {@code null} if not specified.
     */
    public URI getPolicyURI(final LangTag langTag) {

        return policyURIEntries.get(langTag);
    }


    /**
     * Gets the client policy entries for use of end-user data.
     * Corresponds to the {@code policy_uri} client metadata field.
     *
     * @return The policy URI entries, empty map if none.
     */
    public Map<LangTag, URI> getPolicyURIEntries() {

        return policyURIEntries;
    }


    /**
     * Sets the client policy for use of end-user data. Corresponds to the
     * {@code policy_uri} client metadata field, with no language
     * tag.
     *
     * @param policyURI The policy URI, {@code null} if not specified.
     */
    public void setPolicyURI(final URI policyURI) {

        policyURIEntries.put(null, policyURI);
    }


    /**
     * Sets the client policy for use of end-user data. Corresponds to the
     * {@code policy_uri} client metadata field, with an optional
     * language tag.
     *
     * @param policyURI The policy URI. Must not be {@code null}.
     * @param langTag   The language tag, {@code null} if not specified.
     */
    public void setPolicyURI(final URI policyURI, final LangTag langTag) {

        policyURIEntries.put(langTag, policyURI);
    }


    /**
     * Gets the client's terms of service. Corresponds to the
     * {@code tos_uri} client metadata field, with no language
     * tag.
     *
     * @return The terms of service URI, {@code null} if not specified.
     */
    public URI getTermsOfServiceURI() {

        return getTermsOfServiceURI(null);
    }


    /**
     * Gets the client's terms of service. Corresponds to the
     * {@code tos_uri} client metadata field, with an optional
     * language tag.
     *
     * @param langTag The language tag, {@code null} if not specified.
     * @return The terms of service URI, {@code null} if not specified.
     */
    public URI getTermsOfServiceURI(final LangTag langTag) {

        return tosURIEntries.get(langTag);
    }


    /**
     * Gets the client's terms of service entries. Corresponds to the
     * {@code tos_uri} client metadata field.
     *
     * @return The terms of service URI entries, empty map if none.
     */
    public Map<LangTag, URI> getTermsOfServiceURIEntries() {

        return tosURIEntries;
    }


    /**
     * Sets the client's terms of service. Corresponds to the
     * {@code tos_uri} client metadata field, with no language
     * tag.
     *
     * @param tosURI The terms of service URI, {@code null} if not
     *               specified.
     */
    public void setTermsOfServiceURI(final URI tosURI) {

        tosURIEntries.put(null, tosURI);
    }


    /**
     * Sets the client's terms of service. Corresponds to the
     * {@code tos_uri} client metadata field, with an optional
     * language tag.
     *
     * @param tosURI  The terms of service URI. Must not be {@code null}.
     * @param langTag The language tag, {@code null} if not specified.
     */
    public void setTermsOfServiceURI(final URI tosURI, final LangTag langTag) {

        tosURIEntries.put(langTag, tosURI);
    }


    /**
     * Gets the Token endpoint authentication method. Corresponds to the
     * {@code token_endpoint_auth_method} client metadata field.
     *
     * @return The Token endpoint authentication method, {@code null} if
     * not specified.
     */
    public ClientAuthenticationMethod getTokenEndpointAuthMethod() {

        return authMethod;
    }


    /**
     * Sets the Token endpoint authentication method. Corresponds to the
     * {@code token_endpoint_auth_method} client metadata field.
     *
     * @param authMethod The Token endpoint authentication  method,
     *                   {@code null} if not specified.
     */
    public void setTokenEndpointAuthMethod(final ClientAuthenticationMethod authMethod) {

        this.authMethod = authMethod;
    }


    /**
     * Gets the JSON Web Signature (JWS) algorithm required for
     * {@code private_key_jwt} and {@code client_secret_jwt}
     * authentication at the Token endpoint. Corresponds to the
     * {@code token_endpoint_auth_signing_alg} client metadata field.
     *
     * @return The JWS algorithm, {@code null} if not specified.
     */
    public JWSAlgorithm getTokenEndpointAuthJWSAlg() {

        return authJWSAlg;
    }


    /**
     * Sets the JSON Web Signature (JWS) algorithm required for
     * {@code private_key_jwt} and {@code client_secret_jwt}
     * authentication at the Token endpoint. Corresponds to the
     * {@code token_endpoint_auth_signing_alg} client metadata field.
     *
     * @param authJWSAlg The JWS algorithm, {@code null} if not specified.
     */
    public void setTokenEndpointAuthJWSAlg(final JWSAlgorithm authJWSAlg) {

        this.authJWSAlg = authJWSAlg;
    }


    /**
     * Gets the URI for this client's JSON Web Key (JWK) set containing
     * key(s) that are used in signing requests to the server and key(s)
     * for encrypting responses. Corresponds to the {@code jwks_uri} client
     * metadata field.
     *
     * @return The JWK set URI, {@code null} if not specified.
     */
    public URI getJWKSetURI() {

        return jwkSetURI;
    }


    /**
     * Sets the URI for this client's JSON Web Key (JWK) set containing
     * key(s) that are used in signing requests to the server and key(s)
     * for encrypting responses. Corresponds to the {@code jwks_uri} client
     * metadata field.
     *
     * @param jwkSetURI The JWK set URI, {@code null} if not specified.
     */
    public void setJWKSetURI(final URI jwkSetURI) {

        this.jwkSetURI = jwkSetURI;
    }


    /**
     * Gets this client's JSON Web Key (JWK) set containing key(s) that are
     * used in signing requests to the server and key(s) for encrypting
     * responses. Intended as an alternative to {@link #getJWKSetURI} for
     * native clients. Corresponds to the {@code jwks} client metadata
     * field.
     *
     * @return The JWK set, {@code null} if not specified.
     */
    public JWKSet getJWKSet() {

        return jwkSet;
    }


    /**
     * Sets this client's JSON Web Key (JWK) set containing key(s) that are
     * used in signing requests to the server and key(s) for encrypting
     * responses. Intended as an alternative to {@link #getJWKSetURI} for
     * native clients. Corresponds to the {@code jwks} client metadata
     * field.
     *
     * @param jwkSet The JWK set, {@code null} if not specified.
     */
    public void setJWKSet(final JWKSet jwkSet) {

        this.jwkSet = jwkSet;
    }


    /**
     * Gets the pre-registered request object URIs. Corresponds to the
     * {@code request_uris} client metadata field.
     *
     * @return The request object URIs, {@code null} if not specified.
     */
    public Set<URI> getRequestObjectURIs() {

        return requestObjectURIs;
    }


    /**
     * Sets the pre-registered request object URIs. Corresponds to the
     * {@code request_uris} client metadata field.
     *
     * @param requestObjectURIs The request object URIs, {@code null} if
     *                          not specified.
     */
    public void setRequestObjectURIs(final Set<URI> requestObjectURIs) {

        this.requestObjectURIs = requestObjectURIs;
    }


    /**
     * Gets the JSON Web Signature (JWS) algorithm required for request
     * objects sent by this client. Corresponds to the
     * {@code request_object_signing_alg} client metadata field.
     *
     * @return The JWS algorithm, {@code null} if not specified.
     */
    public JWSAlgorithm getRequestObjectJWSAlg() {

        return requestObjectJWSAlg;
    }


    /**
     * Sets the JSON Web Signature (JWS) algorithm required for request
     * objects sent by this client. Corresponds to the
     * {@code request_object_signing_alg} client metadata field.
     *
     * @param requestObjectJWSAlg The JWS algorithm, {@code null} if not
     *                            specified.
     */
    public void setRequestObjectJWSAlg(final JWSAlgorithm requestObjectJWSAlg) {

        this.requestObjectJWSAlg = requestObjectJWSAlg;
    }


    /**
     * Gets the JSON Web Encryption (JWE) algorithm required for request
     * objects sent by this client. Corresponds to the
     * {@code request_object_encryption_alg} client metadata field.
     *
     * @return The JWE algorithm, {@code null} if not specified.
     */
    public JWEAlgorithm getRequestObjectJWEAlg() {

        return requestObjectJWEAlg;
    }


    /**
     * Sets the JSON Web Encryption (JWE) algorithm required for request
     * objects sent by this client. Corresponds to the
     * {@code request_object_encryption_alg} client metadata field.
     *
     * @param requestObjectJWEAlg The JWE algorithm, {@code null} if not
     *                            specified.
     */
    public void setRequestObjectJWEAlg(final JWEAlgorithm requestObjectJWEAlg) {

        this.requestObjectJWEAlg = requestObjectJWEAlg;
    }


    /**
     * Gets the JSON Web Encryption (JWE) method required for request
     * objects sent by this client. Corresponds to the
     * {@code request_object_encryption_enc} client metadata field.
     *
     * @return The JWE method, {@code null} if not specified.
     */
    public EncryptionMethod getRequestObjectJWEEnc() {

        return requestObjectJWEEnc;
    }


    /**
     * Sets the JSON Web Encryption (JWE) method required for request
     * objects sent by this client. Corresponds to the
     * {@code request_object_encryption_enc} client metadata field.
     *
     * @param requestObjectJWEEnc The JWE method, {@code null} if not
     *                            specified.
     */
    public void setRequestObjectJWEEnc(final EncryptionMethod requestObjectJWEEnc) {

        this.requestObjectJWEEnc = requestObjectJWEEnc;
    }


    /**
     * Gets the identifier for the OAuth 2.0 client software. Corresponds
     * to the {@code software_id} client metadata field.
     *
     * @return The software identifier, {@code null} if not specified.
     */
    public SoftwareID getSoftwareID() {

        return softwareID;
    }


    /**
     * Sets the identifier for the OAuth 2.0 client software. Corresponds
     * to the {@code software_id} client metadata field.
     *
     * @param softwareID The software identifier, {@code null} if not
     *                   specified.
     */
    public void setSoftwareID(final SoftwareID softwareID) {

        this.softwareID = softwareID;
    }


    /**
     * Gets the version identifier for the OAuth 2.0 client software.
     * Corresponds to the {@code software_version} client metadata field.
     *
     * @return The version identifier, {@code null} if not specified.
     */
    public SoftwareVersion getSoftwareVersion() {

        return softwareVersion;
    }


    /**
     * Sets the version identifier for the OAuth 2.0 client software.
     * Corresponds to the {@code software_version} client metadata field.
     *
     * @param softwareVersion The version identifier, {@code null} if not
     *                        specified.
     */
    public void setSoftwareVersion(final SoftwareVersion softwareVersion) {

        this.softwareVersion = softwareVersion;
    }


    /**
     * Sets the preference for TLS client certificate bound access tokens.
     * Corresponds to the
     * {@code tls_client_certificate_bound_access_tokens} client metadata
     * field.
     *
     * @return {@code true} indicates a preference for TLS client
     * certificate bound access tokens, {@code false} if none.
     */
    public boolean getTLSClientCertificateBoundAccessTokens() {

        return tlsClientCertificateBoundAccessTokens;
    }


    /**
     * Gets the preference for TLS client certificate bound access tokens.
     * Corresponds to the
     * {@code tls_client_certificate_bound_access_tokens} client metadata
     * field.
     *
     * @param tlsClientCertBoundTokens {@code true} indicates a preference
     *                                 for TLS client certificate bound
     *                                 access tokens, {@code false} if
     *                                 none.
     */
    public void setTLSClientCertificateBoundAccessTokens(final boolean tlsClientCertBoundTokens) {

        tlsClientCertificateBoundAccessTokens = tlsClientCertBoundTokens;
    }


    /**
     * Sets the preference for TLS client certificate bound access tokens.
     * Corresponds to the
     * {@code tls_client_certificate_bound_access_tokens} client metadata
     * field.
     *
     * @return {@code true} indicates a preference for TLS client
     * certificate bound access tokens, {@code false} if none.
     */
    @Deprecated
    public boolean getMutualTLSSenderConstrainedAccessTokens() {

        return tlsClientCertificateBoundAccessTokens;
    }


    /**
     * Gets the preference for TLS client certificate bound access tokens.
     * Corresponds to the
     * {@code tls_client_certificate_bound_access_tokens} client metadata
     * field.
     *
     * @param tlsSenderAccessTokens {@code true} indicates a preference for
     *                              TLS client certificate bound access
     *                              tokens, {@code false} if none.
     */
    @Deprecated
    public void setMutualTLSSenderConstrainedAccessTokens(final boolean tlsSenderAccessTokens) {

        tlsClientCertificateBoundAccessTokens = tlsSenderAccessTokens;
    }


    /**
     * Gets the expected subject distinguished name (DN) of the client
     * X.509 certificate in mutual TLS authentication. Corresponds to the
     * {@code tls_client_auth_subject_dn} client metadata field.
     *
     * @return The expected subject distinguished name (DN) of the client
     * X.509 certificate, {@code null} if not specified.
     */
    public String getTLSClientAuthSubjectDN() {

        return tlsClientAuthSubjectDN;
    }


    /**
     * Sets the expected subject distinguished name (DN) of the client
     * X.509 certificate in mutual TLS authentication. Corresponds to the
     * {@code tls_client_auth_subject_dn} client metadata field.
     *
     * @param subjectDN The expected subject distinguished name (DN) of the
     *                  client X.509 certificate, {@code null} if not
     *                  specified.
     */
    public void setTLSClientAuthSubjectDN(final String subjectDN) {

        this.tlsClientAuthSubjectDN = subjectDN;
    }


    /**
     * Gets the expected dNSName SAN entry in the X.509 certificate, which
     * the OAuth client will use in mutual TLS authentication. Corresponds
     * to the {@code tls_client_auth_san_dns} client metadata field.
     *
     * @return The expected dNSName SAN entry in the X.509 certificate,
     * {@code null} if not specified.
     */
    public String getTLSClientAuthSanDNS() {

        return tlsClientAuthSanDNS;
    }


    /**
     * Sets the expected dNSName SAN entry in the X.509 certificate, which
     * the OAuth client will use in mutual TLS authentication. Corresponds
     * to the {@code tls_client_auth_san_dns} client metadata field.
     *
     * @param dns The expected dNSName SAN entry in the X.509 certificate,
     *            {@code null} if not specified.
     */
    public void setTLSClientAuthSanDNS(final String dns) {

        this.tlsClientAuthSanDNS = dns;
    }


    /**
     * Gets the expected uniformResourceIdentifier SAN entry in the X.509
     * certificate, which the OAuth client will use in mutual TLS
     * authentication. Corresponds to the {@code tls_client_auth_san_uri}
     * client metadata field.
     *
     * @return The expected uniformResourceIdentifier SAN entry in the X.509
     * certificate, {@code null} if not specified.
     */
    public String getTLSClientAuthSanURI() {

        return tlsClientAuthSanURI;
    }


    /**
     * Sets the expected uniformResourceIdentifier SAN entry in the X.509
     * certificate, which the OAuth client will use in mutual TLS
     * authentication. Corresponds to the {@code tls_client_auth_san_uri}
     * client metadata field.
     *
     * @param uri The expected uniformResourceIdentifier SAN entry in the X.509
     *            certificate, {@code null} if not specified.
     */
    public void setTLSClientAuthSanURI(final String uri) {

        this.tlsClientAuthSanURI = uri;
    }


    /**
     * Gets the expected iPAddress SAN entry in the X.509 certificate, which
     * the OAuth client will use in mutual TLS authentication. Corresponds
     * to the {@code tls_client_auth_san_ip} client metadata field.
     *
     * @return The expected iPAddress SAN entry in the X.509 certificate,
     * {@code null} if not specified.
     */
    public String getTLSClientAuthSanIP() {

        return tlsClientAuthSanIP;
    }


    /**
     * Sets the expected iPAddress SAN entry in the X.509 certificate, which
     * the OAuth client will use in mutual TLS authentication. Corresponds
     * to the {@code tls_client_auth_san_ip} client metadata field.
     *
     * @param ip The expected iPAddress SAN entry in the X.509
     *           certificate, {@code null} if not specified.
     */
    public void setTLSClientAuthSanIP(final String ip) {

        this.tlsClientAuthSanIP = ip;
    }


    /**
     * Gets the expected rfc822Name SAN entry in the X.509 certificate, which
     * the OAuth client will use in mutual TLS authentication. Corresponds
     * to the {@code tls_client_auth_san_email} client metadata field.
     *
     * @return The expected rfc822Name SAN entry in the X.509 certificate,
     * {@code null} if not specified.
     */
    public String getTLSClientAuthSanEmail() {

        return tlsClientAuthSanEmail;
    }


    /**
     * Sets the expected rfc822Name SAN entry in the X.509 certificate, which
     * the OAuth client will use in mutual TLS authentication. Corresponds
     * to the {@code tls_client_auth_san_email} client metadata field.
     *
     * @param email The expected rfc822Name SAN entry in the X.509
     *              certificate, {@code null} if not specified.
     */
    public void setTLSClientAuthSanEmail(final String email) {

        this.tlsClientAuthSanEmail = email;
    }


    /**
     * Ensures that for {@code tls_client_auth} a certificate field for the
     * subject is specified. See
     * https://tools.ietf.org/html/draft-ietf-oauth-mtls-15#section-2.1.2
     */
    private void ensureExactlyOneCertSubjectFieldForTLSClientAuth()
            throws IllegalStateException {

        if (!ClientAuthenticationMethod.TLS_CLIENT_AUTH.equals(getTokenEndpointAuthMethod())) {
            // Not tls_client_auth, ignore
            return;
        }

        if (tlsClientAuthSubjectDN == null && tlsClientAuthSanDNS == null && tlsClientAuthSanURI == null && tlsClientAuthSanIP == null && tlsClientAuthSanEmail == null) {
            throw new IllegalStateException("A certificate field must be specified to indicate the subject in tls_client_auth: " +
                    "tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip or tls_client_auth_san_email");
        }

        String exceptionMessage = "Exactly one certificate field must be specified to indicate the subject in tls_client_auth: " +
                "tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip or tls_client_auth_san_email";

        if (tlsClientAuthSubjectDN != null) {
            if (tlsClientAuthSanDNS != null || tlsClientAuthSanURI != null || tlsClientAuthSanIP != null || tlsClientAuthSanEmail != null) {
                throw new IllegalStateException(exceptionMessage);
            }
        }

        if (tlsClientAuthSanDNS != null) {
            if (tlsClientAuthSanURI != null || tlsClientAuthSanIP != null || tlsClientAuthSanEmail != null) {
                throw new IllegalStateException(exceptionMessage);
            }
        }

        if (tlsClientAuthSanURI != null) {
            if (tlsClientAuthSanIP != null || tlsClientAuthSanEmail != null) {
                throw new IllegalStateException(exceptionMessage);
            }
        }

        if (tlsClientAuthSanIP != null) {
            if (tlsClientAuthSanEmail != null) {
                throw new IllegalStateException(exceptionMessage);
            }
        }
    }


    /**
     * Gets the JWS algorithm for JWT-encoded authorisation responses.
     * Corresponds to the {@code authorization_signed_response_alg} client
     * metadata field.
     *
     * @return The JWS algorithm, {@code null} if not specified.
     */
    public JWSAlgorithm getAuthorizationJWSAlg() {

        return authzJWSAlg;
    }


    /**
     * Sets the JWS algorithm for JWT-encoded authorisation responses.
     * Corresponds to the {@code authorization_signed_response_alg} client
     * metadata field.
     *
     * @param authzJWSAlg The JWS algorithm, {@code null} if not specified.
     *                    Must not be {@code "none"}.
     */
    public void setAuthorizationJWSAlg(final JWSAlgorithm authzJWSAlg) {

        if (new JWSAlgorithm("none").equals(authzJWSAlg)) {
            // Prevent passing none as JWS alg
            throw new IllegalArgumentException("The JWS algorithm must not be \"none\"");
        }

        this.authzJWSAlg = authzJWSAlg;
    }


    /**
     * Gets the JWE algorithm for JWT-encoded authorisation responses.
     * Corresponds to the {@code authorization_encrypted_response_alg}
     * client metadata field.
     *
     * @return The JWE algorithm, {@code null} if not specified.
     */
    public JWEAlgorithm getAuthorizationJWEAlg() {

        return authzJWEAlg;
    }


    /**
     * Sets the JWE algorithm for JWT-encoded authorisation responses.
     * Corresponds to the {@code authorization_encrypted_response_alg}
     * client metadata field.
     *
     * @param authzJWEAlg The JWE algorithm, {@code null} if not specified.
     */
    public void setAuthorizationJWEAlg(final JWEAlgorithm authzJWEAlg) {

        this.authzJWEAlg = authzJWEAlg;
    }


    /**
     * Sets the encryption method for JWT-encoded authorisation responses.
     * Corresponds to the {@code authorization_encrypted_response_enc}
     * client metadata field.
     *
     * @return The encryption method, {@code null} if specified.
     */
    public EncryptionMethod getAuthorizationJWEEnc() {

        return authzJWEEnc;
    }


    /**
     * Sets the encryption method for JWT-encoded authorisation responses.
     * Corresponds to the {@code authorization_encrypted_response_enc}
     * client metadata field.
     *
     * @param authzJWEEnc The encryption method, {@code null} if specified.
     */
    public void setAuthorizationJWEEnc(final EncryptionMethod authzJWEEnc) {

        this.authzJWEEnc = authzJWEEnc;
    }


    /**
     * Gets the specified custom metadata field.
     *
     * @param name The field name. Must not be {@code null}.
     * @return The field value, typically serialisable to a JSON entity,
     * {@code null} if none.
     */
    public Object getCustomField(final String name) {

        return customFields.get(name);
    }


    /**
     * Gets the custom metadata fields.
     *
     * @return The custom metadata fields, as a JSON object, empty object
     * if none.
     */
    public JsonObject getCustomFields() {

        return customFields;
    }


    /**
     * Sets the specified custom metadata field.
     *
     * @param name  The field name. Must not be {@code null}.
     * @param value The field value. Should serialise to a JSON entity.
     */
    public void setCustomField(final String name, final Object value) {

        // TODO not the most performant way, but does it hurt? is it used?
        JsonObjectBuilder temp = Json.createObjectBuilder(customFields);
        JSONObjectUtils.addValue(temp, name, value);
        customFields = temp.build();
    }


    /**
     * Sets the custom metadata fields.
     *
     * @param customFields The custom metadata fields, as a JSON object,
     *                     empty object if none. Must not be {@code null}.
     */
    public void setCustomFields(final JsonObject customFields) {

        if (customFields == null) {
            throw new IllegalArgumentException("The custom fields JSON object must not be null");
        }

        this.customFields = customFields;
    }


    /**
     * Applies the client metadata defaults where no values have been
     * specified.
     *
     * <ul>
     *     <li>The response types default to {@code ["code"]}.
     *     <li>The grant types default to {@code ["authorization_code"]}.
     *     <li>The client authentication method defaults to
     *         "client_secret_basic", unless the grant type is "implicit"
     *         only.
     *     <li>The encryption method for JWT-encoded authorisation
     *         responses defaults to {@code A128CBC-HS256} if a JWE
     *         algorithm is set.
     * </ul>
     */
    public void applyDefaults() {

        if (responseTypes == null) {
            responseTypes = new HashSet<>();
            responseTypes.add(ResponseType.getDefault());
        }

        if (grantTypes == null) {
            grantTypes = new HashSet<>();
            grantTypes.add(GrantType.AUTHORIZATION_CODE);
        }

        if (authMethod == null) {

            if (grantTypes.contains(GrantType.IMPLICIT) && grantTypes.size() == 1) {
                authMethod = ClientAuthenticationMethod.NONE;
            } else {
                authMethod = ClientAuthenticationMethod.getDefault();
            }
        }

        if (authzJWEAlg != null && authzJWEEnc == null) {
            authzJWEEnc = EncryptionMethod.A128CBC_HS256;
        }
    }


    /**
     * Returns the JSON object representation of this client metadata,
     * including any custom fields.
     *
     * @return The JSON object.
     */
    public JsonObjectBuilder toJSONObject() {

        return toJSONObject(true);
    }


    /**
     * Returns the JSON object representation of this client metadata.
     *
     * @param includeCustomFields {@code true} to include any custom
     *                            metadata fields, {@code false} to omit
     *                            them.
     * @return The JSON object.
     */
    public JsonObjectBuilder toJSONObject(final boolean includeCustomFields) {

        JsonObjectBuilder result;

        result = Json.createObjectBuilder();
        if (includeCustomFields) {
            for (Map.Entry<String, JsonValue> entry : customFields.entrySet()) {
                result.add(entry.getKey(), entry.getValue());
            }
        }

        if (redirectURIs != null) {

            JsonArrayBuilder uriList = Json.createArrayBuilder();

            for (URI uri : redirectURIs) {
                uriList.add(uri.toString());
            }
            result.add("redirect_uris", uriList.build());
        }


        if (scope != null) {
            result.add("scope", scope.toString());
        }


        if (responseTypes != null) {

            JsonArrayBuilder rtList = Json.createArrayBuilder();

            for (ResponseType rt : responseTypes) {
                rtList.add(rt.toString());
            }
            result.add("response_types", rtList.build());
        }


        if (grantTypes != null) {

            JsonArrayBuilder grantList = Json.createArrayBuilder();

            for (GrantType grant : grantTypes) {
                grantList.add(grant.toString());
            }
            result.add("grant_types", grantList.build());
        }


        if (contacts != null) {
            JsonArrayBuilder contactList = Json.createArrayBuilder();
            for (String contact : contacts) {
                contactList.add(contact);
            }
            result.add("contacts", contactList.build());
        }


        if (!nameEntries.isEmpty()) {

            for (Map.Entry<LangTag, String> entry : nameEntries.entrySet()) {

                LangTag langTag = entry.getKey();
                String name = entry.getValue();

                if (name == null) {
                    continue;
                }

                if (langTag == null) {
                    result.add("client_name", entry.getValue());
                } else {
                    result.add("client_name#" + langTag, entry.getValue());
                }
            }
        }


        if (!logoURIEntries.isEmpty()) {

            for (Map.Entry<LangTag, URI> entry : logoURIEntries.entrySet()) {

                LangTag langTag = entry.getKey();
                URI uri = entry.getValue();

                if (uri == null) {
                    continue;
                }

                if (langTag == null) {
                    result.add("logo_uri", entry.getValue().toString());
                } else {
                    result.add("logo_uri#" + langTag, entry.getValue().toString());
                }
            }
        }


        if (!uriEntries.isEmpty()) {

            for (Map.Entry<LangTag, URI> entry : uriEntries.entrySet()) {

                LangTag langTag = entry.getKey();
                URI uri = entry.getValue();

                if (uri == null) {
                    continue;
                }

                if (langTag == null) {
                    result.add("client_uri", entry.getValue().toString());
                } else {
                    result.add("client_uri#" + langTag, entry.getValue().toString());
                }
            }
        }


        if (!policyURIEntries.isEmpty()) {

            for (Map.Entry<LangTag, URI> entry : policyURIEntries.entrySet()) {

                LangTag langTag = entry.getKey();
                URI uri = entry.getValue();

                if (uri == null) {
                    continue;
                }

                if (langTag == null) {
                    result.add("policy_uri", entry.getValue().toString());
                } else {
                    result.add("policy_uri#" + langTag, entry.getValue().toString());
                }
            }
        }


        if (!tosURIEntries.isEmpty()) {

            for (Map.Entry<LangTag, URI> entry : tosURIEntries.entrySet()) {

                LangTag langTag = entry.getKey();
                URI uri = entry.getValue();

                if (uri == null) {
                    continue;
                }

                if (langTag == null) {
                    result.add("tos_uri", entry.getValue().toString());
                } else {
                    result.add("tos_uri#" + langTag, entry.getValue().toString());
                }
            }
        }


        if (authMethod != null) {
            result.add("token_endpoint_auth_method", authMethod.toString());
        }


        if (authJWSAlg != null) {
            result.add("token_endpoint_auth_signing_alg", authJWSAlg.getName());
        }


        if (jwkSetURI != null) {
            result.add("jwks_uri", jwkSetURI.toString());
        }


        if (jwkSet != null) {
            result.add("jwks", jwkSet.toJSONObject(true)); // prevent private keys from leaking
        }


        if (requestObjectURIs != null) {

            JsonArrayBuilder uriList = Json.createArrayBuilder();


            for (URI uri : requestObjectURIs) {
                uriList.add(uri.toString());
            }

            result.add("request_uris", uriList);
        }


        if (requestObjectJWSAlg != null) {
            result.add("request_object_signing_alg", requestObjectJWSAlg.getName());
        }

        if (requestObjectJWEAlg != null) {
            result.add("request_object_encryption_alg", requestObjectJWEAlg.getName());
        }

        if (requestObjectJWEEnc != null) {
            result.add("request_object_encryption_enc", requestObjectJWEEnc.getName());
        }


        if (softwareID != null) {
            result.add("software_id", softwareID.getValue());
        }

        if (softwareVersion != null) {
            result.add("software_version", softwareVersion.getValue());
        }

        result.add("tls_client_certificate_bound_access_tokens", tlsClientCertificateBoundAccessTokens);

        if (tlsClientAuthSubjectDN != null) {
            result.add("tls_client_auth_subject_dn", tlsClientAuthSubjectDN);
        }
        if (tlsClientAuthSanDNS != null) {
            result.add("tls_client_auth_san_dns", tlsClientAuthSanDNS);
        }

        if (tlsClientAuthSanURI != null) {
            result.add("tls_client_auth_san_uri", tlsClientAuthSanURI);
        }

        if (tlsClientAuthSanIP != null) {
            result.add("tls_client_auth_san_ip", tlsClientAuthSanIP);
        }

        if (tlsClientAuthSanEmail != null) {
            result.add("tls_client_auth_san_email", tlsClientAuthSanEmail);
        }

        if (authzJWSAlg != null) {
            result.add("authorization_signed_response_alg", authzJWSAlg.getName());
        }

        if (authzJWEAlg != null) {
            result.add("authorization_encrypted_response_alg", authzJWEAlg.getName());
        }

        if (authzJWEEnc != null) {
            result.add("authorization_encrypted_response_enc", authzJWEEnc.getName());
        }

        return result;
    }


    @Override
    public String toString() {
        return toJSONObject().build().toString();
    }


    /**
     * Parses an client metadata instance from the specified JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The client metadata.
     * @throws ParseException If the JSON object couldn't be parsed to a
     *                        client metadata instance.
     */
    public static ClientMetadata parse(final JsonObject jsonObject)
            throws OAuth2JSONParseException {

        // Copy JSON object, then parse
        return parseFromModifiableJSONObject(Json.createObjectBuilder(jsonObject).build());
    }


    /**
     * Parses an client metadata instance from the specified JSON object.
     *
     * @param jsonObject The JSON object to parse, will be modified by
     *                   the parse routine. Must not be {@code null}.
     * @return The client metadata.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to a
     *                                  client metadata instance.
     */
    private static ClientMetadata parseFromModifiableJSONObject(final JsonObject jsonObject)
            throws OAuth2JSONParseException {

        ClientMetadata metadata = new ClientMetadata();

        if (jsonObject.get("redirect_uris") != null) {

            Set<URI> redirectURIs = new LinkedHashSet<>();

            for (String uriString : JSONObjectUtils.getStringList(jsonObject, "redirect_uris")) {
                URI uri;
                try {
                    uri = new URI(uriString);
                } catch (URISyntaxException e) {
                    throw new OAuth2JSONParseException("Invalid \"redirect_uris\" parameter: " + e.getMessage(), RegistrationError.INVALID_REDIRECT_URI.appendDescription(": " + e.getMessage()));
                }

                if (uri.getFragment() != null) {
                    String detail = "URI must not contain fragment";
                    throw new OAuth2JSONParseException("Invalid \"redirect_uris\" parameter: " + detail, RegistrationError.INVALID_REDIRECT_URI.appendDescription(": " + detail));
                }

                redirectURIs.add(uri);
            }

            metadata.setRedirectionURIs(redirectURIs);
            jsonObject.remove("redirect_uris");
        }

        try {

            if (jsonObject.get("scope") != null) {
                metadata.setScope(Scope.parse(jsonObject.getString("scope")));
                jsonObject.remove("scope");
            }


            if (jsonObject.get("response_types") != null) {

                Set<ResponseType> responseTypes = new LinkedHashSet<>();

                for (String rt : JSONObjectUtils.getStringList(jsonObject, "response_types")) {

                    responseTypes.add(ResponseType.parse(rt));
                }

                metadata.setResponseTypes(responseTypes);
                jsonObject.remove("response_types");
            }


            if (jsonObject.get("grant_types") != null) {

                Set<GrantType> grantTypes = new LinkedHashSet<>();

                for (String grant : JSONObjectUtils.getStringList(jsonObject, "grant_types")) {

                    grantTypes.add(GrantType.parse(grant));
                }

                metadata.setGrantTypes(grantTypes);
                jsonObject.remove("grant_types");
            }


            if (jsonObject.get("contacts") != null) {
                metadata.setEmailContacts(JSONObjectUtils.getStringList(jsonObject, "contacts"));
                jsonObject.remove("contacts");
            }


            // Find lang-tagged client_name params
            Map<LangTag, Object> matches = LangTagUtils.find("client_name", jsonObject);

            for (Map.Entry<LangTag, Object> entry : matches.entrySet()) {

                try {
                    metadata.setName((String) entry.getValue(), entry.getKey());

                } catch (ClassCastException e) {

                    throw new OAuth2JSONParseException("Invalid \"client_name\" (language tag) parameter");
                }

                removeMember(jsonObject, "client_name", entry.getKey());
            }


            matches = LangTagUtils.find("logo_uri", jsonObject);

            for (Map.Entry<LangTag, Object> entry : matches.entrySet()) {

                if (entry.getValue() == null) {
                    continue;
                }

                try {
                    metadata.setLogoURI(new URI((String) entry.getValue()), entry.getKey());

                } catch (Exception e) {

                    throw new OAuth2JSONParseException("Invalid \"logo_uri\" (language tag) parameter");
                }

                removeMember(jsonObject, "logo_uri", entry.getKey());
            }


            matches = LangTagUtils.find("client_uri", jsonObject);

            for (Map.Entry<LangTag, Object> entry : matches.entrySet()) {

                if (entry.getValue() == null) {
                    continue;
                }

                try {
                    metadata.setURI(new URI((String) entry.getValue()), entry.getKey());


                } catch (Exception e) {

                    throw new OAuth2JSONParseException("Invalid \"client_uri\" (language tag) parameter");
                }

                removeMember(jsonObject, "client_uri", entry.getKey());
            }


            matches = LangTagUtils.find("policy_uri", jsonObject);

            for (Map.Entry<LangTag, Object> entry : matches.entrySet()) {

                if (entry.getValue() == null) {
                    continue;
                }

                try {
                    metadata.setPolicyURI(new URI((String) entry.getValue()), entry.getKey());

                } catch (Exception e) {

                    throw new OAuth2JSONParseException("Invalid \"policy_uri\" (language tag) parameter");
                }

                removeMember(jsonObject, "policy_uri", entry.getKey());
            }


            matches = LangTagUtils.find("tos_uri", jsonObject);

            for (Map.Entry<LangTag, Object> entry : matches.entrySet()) {

                if (entry.getValue() == null) {
                    continue;
                }

                try {
                    metadata.setTermsOfServiceURI(new URI((String) entry.getValue()), entry.getKey());

                } catch (Exception e) {

                    throw new OAuth2JSONParseException("Invalid \"tos_uri\" (language tag) parameter");
                }

                removeMember(jsonObject, "tos_uri", entry.getKey());
            }


            if (jsonObject.get("token_endpoint_auth_method") != null) {
                metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.parse(
                        jsonObject.getString("token_endpoint_auth_method")));

                jsonObject.remove("token_endpoint_auth_method");
            }


            if (jsonObject.get("token_endpoint_auth_signing_alg") != null) {
                metadata.setTokenEndpointAuthJWSAlg(JWSAlgorithm.parse(
                        jsonObject.getString("token_endpoint_auth_signing_alg")));

                jsonObject.remove("token_endpoint_auth_signing_alg");
            }


            if (jsonObject.get("jwks_uri") != null) {
                metadata.setJWKSetURI(JSONObjectUtils.getURI(jsonObject, "jwks_uri"));
                jsonObject.remove("jwks_uri");
            }

            if (jsonObject.get("jwks") != null) {

                try {
                    metadata.setJWKSet(JWKSet.parse(jsonObject.getString("jwks")));

                } catch (java.text.ParseException e) {
                    throw new OAuth2JSONParseException(e.getMessage(), e);
                }

                jsonObject.remove("jwks");
            }

            if (jsonObject.get("request_uris") != null) {

                Set<URI> requestURIs = new LinkedHashSet<>();

                for (String uriString : JSONObjectUtils.getStringList(jsonObject, "request_uris")) {

                    try {
                        requestURIs.add(new URI(uriString));

                    } catch (URISyntaxException e) {

                        throw new OAuth2JSONParseException("Invalid \"request_uris\" parameter");
                    }
                }

                metadata.setRequestObjectURIs(requestURIs);
                jsonObject.remove("request_uris");
            }

            if (jsonObject.get("request_object_signing_alg") != null) {
                metadata.setRequestObjectJWSAlg(JWSAlgorithm.parse(
                        jsonObject.getString("request_object_signing_alg")));

                jsonObject.remove("request_object_signing_alg");
            }

            if (jsonObject.get("request_object_encryption_alg") != null) {
                metadata.setRequestObjectJWEAlg(JWEAlgorithm.parse(
                        jsonObject.getString("request_object_encryption_alg")));

                jsonObject.remove("request_object_encryption_alg");
            }

            if (jsonObject.get("request_object_encryption_enc") != null) {
                metadata.setRequestObjectJWEEnc(EncryptionMethod.parse(
                        jsonObject.getString("request_object_encryption_enc")));

                jsonObject.remove("request_object_encryption_enc");
            }

            if (jsonObject.get("software_id") != null) {
                metadata.setSoftwareID(new SoftwareID(jsonObject.getString("software_id")));
                jsonObject.remove("software_id");
            }

            if (jsonObject.get("software_version") != null) {
                metadata.setSoftwareVersion(new SoftwareVersion(jsonObject.getString("software_version")));
                jsonObject.remove("software_version");
            }

            if (jsonObject.get("tls_client_certificate_bound_access_tokens") != null) {
                metadata.setTLSClientCertificateBoundAccessTokens(jsonObject.getBoolean("tls_client_certificate_bound_access_tokens"));
                jsonObject.remove("tls_client_certificate_bound_access_tokens");
            }

            if (jsonObject.get("tls_client_auth_subject_dn") != null) {
                metadata.setTLSClientAuthSubjectDN(jsonObject.getString("tls_client_auth_subject_dn"));
                jsonObject.remove("tls_client_auth_subject_dn");
            }

            if (jsonObject.get("tls_client_auth_san_dns") != null) {
                metadata.setTLSClientAuthSanDNS(jsonObject.getString("tls_client_auth_san_dns"));
                jsonObject.remove("tls_client_auth_san_dns");
            }

            if (jsonObject.get("tls_client_auth_san_uri") != null) {
                metadata.setTLSClientAuthSanURI(jsonObject.getString("tls_client_auth_san_uri"));
                jsonObject.remove("tls_client_auth_san_uri");
            }

            if (jsonObject.get("tls_client_auth_san_ip") != null) {
                metadata.setTLSClientAuthSanIP(jsonObject.getString("tls_client_auth_san_ip"));
                jsonObject.remove("tls_client_auth_san_ip");
            }

            if (jsonObject.get("tls_client_auth_san_email") != null) {
                metadata.setTLSClientAuthSanEmail(jsonObject.getString("tls_client_auth_san_email"));
                jsonObject.remove("tls_client_auth_san_email");
            }

            metadata.ensureExactlyOneCertSubjectFieldForTLSClientAuth();

            if (jsonObject.get("authorization_signed_response_alg") != null) {
                metadata.setAuthorizationJWSAlg(JWSAlgorithm.parse(jsonObject.getString("authorization_signed_response_alg")));
                jsonObject.remove("authorization_signed_response_alg");
            }

            if (jsonObject.get("authorization_encrypted_response_alg") != null) {
                metadata.setAuthorizationJWEAlg(JWEAlgorithm.parse(jsonObject.getString("authorization_encrypted_response_alg")));
                jsonObject.remove("authorization_encrypted_response_alg");
            }

            if (jsonObject.get("authorization_encrypted_response_enc") != null) {
                metadata.setAuthorizationJWEEnc(EncryptionMethod.parse(jsonObject.getString("authorization_encrypted_response_enc")));
                jsonObject.remove("authorization_encrypted_response_enc");
            }

        } catch (ParseException | IllegalStateException e) {
            // Insert client_client_metadata error code so that it
            // can be reported back to the client if we have a
            // registration event
            throw new OAuth2JSONParseException(e.getMessage(), RegistrationError.INVALID_CLIENT_METADATA.appendDescription(": " + e.getMessage()), e.getCause());
        }

        // The remaining fields are custom
        metadata.customFields = jsonObject;

        return metadata;
    }


    /**
     * Removes a JSON object member with the specified base name and
     * optional language tag.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @param name       The base member name. Must not be {@code null}.
     * @param langTag    The language tag, {@code null} if none.
     */
    private static void removeMember(final JsonObject jsonObject, final String name, final LangTag langTag) {

        if (langTag == null) {
            jsonObject.remove(name);
        } else {
            jsonObject.remove(name + "#" + langTag);
        }
    }
}
