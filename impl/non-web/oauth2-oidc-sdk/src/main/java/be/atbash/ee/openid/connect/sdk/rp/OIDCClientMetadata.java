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
package be.atbash.ee.openid.connect.sdk.rp;


import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.client.ClientMetadata;
import be.atbash.ee.oauth2.sdk.client.RegistrationError;
import be.atbash.ee.oauth2.sdk.util.CollectionUtils;
import be.atbash.ee.oauth2.sdk.util.JSONArrayUtils;
import be.atbash.ee.openid.connect.sdk.SubjectType;
import be.atbash.ee.openid.connect.sdk.claims.ACR;
import be.atbash.ee.openid.connect.sdk.id.SectorID;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.IncorrectJsonValueException;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.*;


/**
 * OpenID Connect client metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.
 *     <li>OpenID Connect Session Management 1.0, section 5.1.1 (draft 28).
 *     <li>OpenID Connect Front-Channel Logout 1.0, section 2 (draft 02).
 *     <li>OpenID Connect Back-Channel Logout 1.0, section 2.2 (draft 04).
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         2.
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (draft-ietf-oauth-mtls-15), sections 2.1.2 and 3.4.
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 * </ul>
 */
public class OIDCClientMetadata extends ClientMetadata {


    /**
     * The registered parameter names.
     */
    private static final Set<String> REGISTERED_PARAMETER_NAMES;


    static {
        // Start with the base OAuth 2.0 client params
        Set<String> p = new HashSet<>(ClientMetadata.getRegisteredParameterNames());

        // OIDC params
        p.add("application_type");
        p.add("subject_type");
        p.add("sector_identifier_uri");
        p.add("id_token_signed_response_alg");
        p.add("id_token_encrypted_response_alg");
        p.add("id_token_encrypted_response_enc");
        p.add("userinfo_signed_response_alg");
        p.add("userinfo_encrypted_response_alg");
        p.add("userinfo_encrypted_response_enc");
        p.add("default_max_age");
        p.add("require_auth_time");
        p.add("default_acr_values");
        p.add("initiate_login_uri");

        // OIDC session
        p.add("post_logout_redirect_uris");

        // OIDC logout
        p.add("frontchannel_logout_uri");
        p.add("frontchannel_logout_session_required");
        p.add("backchannel_logout_uri");
        p.add("backchannel_logout_session_required");

        REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
    }


    /**
     * The client application type.
     */
    private ApplicationType applicationType;


    /**
     * The subject identifier type for responses to this client.
     */
    private SubjectType subjectType;


    /**
     * Sector identifier URI.
     */
    private URI sectorIDURI;


    /**
     * The JSON Web Signature (JWS) algorithm required for the ID Tokens
     * issued to this client.
     */
    private JWSAlgorithm idTokenJWSAlg;


    /**
     * The JSON Web Encryption (JWE) algorithm required for the ID Tokens
     * issued to this client.
     */
    private JWEAlgorithm idTokenJWEAlg;


    /**
     * The JSON Web Encryption (JWE) method required for the ID Tokens
     * issued to this client.
     */
    private EncryptionMethod idTokenJWEEnc;


    /**
     * The JSON Web Signature (JWS) algorithm required for the UserInfo
     * responses to this client.
     */
    private JWSAlgorithm userInfoJWSAlg;


    /**
     * The JSON Web Encryption (JWE) algorithm required for the UserInfo
     * responses to this client.
     */
    private JWEAlgorithm userInfoJWEAlg;


    /**
     * The JSON Web Encryption (JWE) method required for the UserInfo
     * responses to this client.
     */
    private EncryptionMethod userInfoJWEEnc;


    /**
     * The default max authentication age, in seconds. If not specified 0.
     */
    private int defaultMaxAge = -1;


    /**
     * If {@code true} the {@code auth_time} claim in the ID Token is
     * required by default.
     */
    private boolean requiresAuthTime;


    /**
     * The default Authentication Context Class Reference (ACR) values, by
     * order of preference.
     */
    private List<ACR> defaultACRs;


    /**
     * Authorisation server initiated login HTTPS URI.
     */
    private URI initiateLoginURI;


    /**
     * Logout redirection URIs.
     */
    private Set<URI> postLogoutRedirectURIs;


    /**
     * Front-channel logout URI.
     */
    private URI frontChannelLogoutURI;


    /**
     * Indicates requirement for a session identifier on front-channel
     * logout.
     */
    private boolean frontChannelLogoutSessionRequired = false;


    /**
     * Back-channel logout URI.
     */
    private URI backChannelLogoutURI;


    /**
     * Indicates requirement for a session identifier on back-channel
     * logout.
     */
    private boolean backChannelLogoutSessionRequired = false;


    /**
     * Creates a new OpenID Connect client metadata instance.
     */
    public OIDCClientMetadata() {

        super();
    }


    /**
     * Creates a new OpenID Connect client metadata instance from the
     * specified base OAuth 2.0 client metadata.
     *
     * @param metadata The base OAuth 2.0 client metadata. Must not be
     *                 {@code null}.
     */
    public OIDCClientMetadata(ClientMetadata metadata) {

        super(metadata);
    }


    /**
     * Gets the registered (standard) OpenID Connect client metadata
     * parameter names.
     *
     * @return The registered OpenID Connect parameter names, as an
     * unmodifiable set.
     */
    public static Set<String> getRegisteredParameterNames() {

        return REGISTERED_PARAMETER_NAMES;
    }


    /**
     * Gets the client application type. Corresponds to the
     * {@code application_type} client metadata field.
     *
     * @return The client application type, {@code null} if not specified.
     */
    public ApplicationType getApplicationType() {

        return applicationType;
    }


    /**
     * Sets the client application type. Corresponds to the
     * {@code application_type} client metadata field.
     *
     * @param applicationType The client application type, {@code null} if
     *                        not specified.
     */
    public void setApplicationType(ApplicationType applicationType) {

        this.applicationType = applicationType;
    }


    /**
     * Gets the subject identifier type for responses to this client.
     * Corresponds to the {@code subject_type} client metadata field.
     *
     * @return The subject identifier type, {@code null} if not specified.
     */
    public SubjectType getSubjectType() {

        return subjectType;
    }


    /**
     * Sets the subject identifier type for responses to this client.
     * Corresponds to the {@code subject_type} client metadata field.
     *
     * @param subjectType The subject identifier type, {@code null} if not
     *                    specified.
     */
    public void setSubjectType(SubjectType subjectType) {

        this.subjectType = subjectType;
    }


    /**
     * Gets the sector identifier URI. Corresponds to the
     * {@code sector_identifier_uri} client metadata field.
     *
     * @return The sector identifier URI, {@code null} if not specified.
     */
    public URI getSectorIDURI() {

        return sectorIDURI;
    }


    /**
     * Sets the sector identifier URI. Corresponds to the
     * {@code sector_identifier_uri} client metadata field.
     *
     * @param sectorIDURI The sector identifier URI, {@code null} if not
     *                    specified.
     */
    public void setSectorIDURI(URI sectorIDURI) {

        if (sectorIDURI != null) {
            SectorID.ensureHTTPScheme(sectorIDURI);
            SectorID.ensureHostComponent(sectorIDURI);
        }

        this.sectorIDURI = sectorIDURI;
    }


    /**
     * Resolves the sector identifier from the client metadata.
     *
     * @return The sector identifier, {@code null} if the subject type is
     * set to public.
     * @throws IllegalStateException If resolution failed due to incomplete
     *                               or inconsistent metadata.
     */
    public SectorID resolveSectorID() {

        if (!SubjectType.PAIRWISE.equals(getSubjectType())) {
            // subject type is not pairwise or null
            return null;
        }

        // Check sector identifier URI first
        if (getSectorIDURI() != null) {
            return new SectorID(getSectorIDURI());
        }

        // Check redirect URIs second
        if (CollectionUtils.isEmpty(getRedirectionURIs())) {
            throw new IllegalStateException("Couldn't resolve sector ID: Missing redirect_uris");
        }

        if (getRedirectionURIs().size() > 1) {
            throw new IllegalStateException("Couldn't resolve sector ID: More than one redirect_uri, sector_identifier_uri not specified");
        }

        return new SectorID(getRedirectionURIs().iterator().next());
    }


    /**
     * Gets the JSON Web Signature (JWS) algorithm required for the ID
     * Tokens issued to this client. Corresponds to the
     * {@code id_token_signed_response_alg} client metadata field.
     *
     * @return The JWS algorithm, {@code null} if not specified.
     */
    public JWSAlgorithm getIDTokenJWSAlg() {

        return idTokenJWSAlg;
    }


    /**
     * Sets the JSON Web Signature (JWS) algorithm required for the ID
     * Tokens issued to this client. Corresponds to the
     * {@code id_token_signed_response_alg} client metadata field.
     *
     * @param idTokenJWSAlg The JWS algorithm, {@code null} if not
     *                      specified.
     */
    public void setIDTokenJWSAlg(JWSAlgorithm idTokenJWSAlg) {

        this.idTokenJWSAlg = idTokenJWSAlg;
    }


    /**
     * Gets the JSON Web Encryption (JWE) algorithm required for the ID
     * Tokens issued to this client. Corresponds to the
     * {@code id_token_encrypted_response_alg} client metadata field.
     *
     * @return The JWE algorithm, {@code null} if not specified.
     */
    public JWEAlgorithm getIDTokenJWEAlg() {

        return idTokenJWEAlg;
    }


    /**
     * Sets the JSON Web Encryption (JWE) algorithm required for the ID
     * Tokens issued to this client. Corresponds to the
     * {@code id_token_encrypted_response_alg} client metadata field.
     *
     * @param idTokenJWEAlg The JWE algorithm, {@code null} if not
     *                      specified.
     */
    public void setIDTokenJWEAlg(JWEAlgorithm idTokenJWEAlg) {

        this.idTokenJWEAlg = idTokenJWEAlg;
    }


    /**
     * Gets the JSON Web Encryption (JWE) method required for the ID Tokens
     * issued to this client. Corresponds to the
     * {@code id_token_encrypted_response_enc} client metadata field.
     *
     * @return The JWE method, {@code null} if not specified.
     */
    public EncryptionMethod getIDTokenJWEEnc() {

        return idTokenJWEEnc;
    }


    /**
     * Sets the JSON Web Encryption (JWE) method required for the ID Tokens
     * issued to this client. Corresponds to the
     * {@code id_token_encrypted_response_enc} client metadata field.
     *
     * @param idTokenJWEEnc The JWE method, {@code null} if not specified.
     */
    public void setIDTokenJWEEnc(EncryptionMethod idTokenJWEEnc) {

        this.idTokenJWEEnc = idTokenJWEEnc;
    }


    /**
     * Gets the JSON Web Signature (JWS) algorithm required for the
     * UserInfo responses to this client. Corresponds to the
     * {@code userinfo_signed_response_alg} client metadata field.
     *
     * @return The JWS algorithm, {@code null} if not specified.
     */
    public JWSAlgorithm getUserInfoJWSAlg() {

        return userInfoJWSAlg;
    }


    /**
     * Sets the JSON Web Signature (JWS) algorithm required for the
     * UserInfo responses to this client. Corresponds to the
     * {@code userinfo_signed_response_alg} client metadata field.
     *
     * @param userInfoJWSAlg The JWS algorithm, {@code null} if not
     *                       specified.
     */
    public void setUserInfoJWSAlg(JWSAlgorithm userInfoJWSAlg) {

        this.userInfoJWSAlg = userInfoJWSAlg;
    }


    /**
     * Gets the JSON Web Encryption (JWE) algorithm required for the
     * UserInfo responses to this client. Corresponds to the
     * {@code userinfo_encrypted_response_alg} client metadata field.
     *
     * @return The JWE algorithm, {@code null} if not specified.
     */
    public JWEAlgorithm getUserInfoJWEAlg() {

        return userInfoJWEAlg;
    }


    /**
     * Sets the JSON Web Encryption (JWE) algorithm required for the
     * UserInfo responses to this client. Corresponds to the
     * {@code userinfo_encrypted_response_alg} client metadata field.
     *
     * @param userInfoJWEAlg The JWE algorithm, {@code null} if not
     *                       specified.
     */
    public void setUserInfoJWEAlg(JWEAlgorithm userInfoJWEAlg) {

        this.userInfoJWEAlg = userInfoJWEAlg;
    }


    /**
     * Gets the JSON Web Encryption (JWE) method required for the UserInfo
     * responses to this client. Corresponds to the
     * {@code userinfo_encrypted_response_enc} client metadata field.
     *
     * @return The JWE method, {@code null} if not specified.
     */
    public EncryptionMethod getUserInfoJWEEnc() {

        return userInfoJWEEnc;
    }


    /**
     * Sets the JSON Web Encryption (JWE) method required for the UserInfo
     * responses to this client. Corresponds to the
     * {@code userinfo_encrypted_response_enc} client metadata field.
     *
     * @param userInfoJWEEnc The JWE method, {@code null} if not specified.
     */
    public void setUserInfoJWEEnc(EncryptionMethod userInfoJWEEnc) {

        this.userInfoJWEEnc = userInfoJWEEnc;
    }


    /**
     * Gets the default maximum authentication age. Corresponds to the
     * {@code default_max_age} client metadata field.
     *
     * @return The default max authentication age, in seconds. If not
     * specified -1.
     */
    public int getDefaultMaxAge() {

        return defaultMaxAge;
    }


    /**
     * Sets the default maximum authentication age. Corresponds to the
     * {@code default_max_age} client metadata field.
     *
     * @param defaultMaxAge The default max authentication age, in seconds.
     *                      If not specified -1.
     */
    public void setDefaultMaxAge(int defaultMaxAge) {

        this.defaultMaxAge = defaultMaxAge;
    }


    /**
     * Gets the default requirement for the {@code auth_time} claim in the
     * ID Token. Corresponds to the {@code require_auth_time} client
     * metadata field.
     *
     * @return If {@code true} the {@code auth_Time} claim in the ID Token
     * is required by default.
     */
    public boolean requiresAuthTime() {

        return requiresAuthTime;
    }


    /**
     * Sets the default requirement for the {@code auth_time} claim in the
     * ID Token. Corresponds to the {@code require_auth_time} client
     * metadata field.
     *
     * @param requiresAuthTime If {@code true} the {@code auth_Time} claim
     *                         in the ID Token is required by default.
     */
    public void requiresAuthTime(boolean requiresAuthTime) {

        this.requiresAuthTime = requiresAuthTime;
    }


    /**
     * Gets the default Authentication Context Class Reference (ACR)
     * values. Corresponds to the {@code default_acr_values} client
     * metadata field.
     *
     * @return The default ACR values, by order of preference,
     * {@code null} if not specified.
     */
    public List<ACR> getDefaultACRs() {

        return defaultACRs;
    }


    /**
     * Sets the default Authentication Context Class Reference (ACR)
     * values. Corresponds to the {@code default_acr_values} client
     * metadata field.
     *
     * @param defaultACRs The default ACRs, by order of preference,
     *                    {@code null} if not specified.
     */
    public void setDefaultACRs(List<ACR> defaultACRs) {

        this.defaultACRs = defaultACRs;
    }


    /**
     * Gets the HTTPS URI that the authorisation server can call to
     * initiate a login at the client. Corresponds to the
     * {@code initiate_login_uri} client metadata field.
     *
     * @return The login URI, {@code null} if not specified.
     */
    public URI getInitiateLoginURI() {

        return initiateLoginURI;
    }


    /**
     * Sets the HTTPS URI that the authorisation server can call to
     * initiate a login at the client. Corresponds to the
     * {@code initiate_login_uri} client metadata field.
     *
     * @param loginURI The login URI, {@code null} if not specified.
     */
    public void setInitiateLoginURI(URI loginURI) {

        this.initiateLoginURI = loginURI;
    }


    /**
     * Gets the post logout redirection URIs. Corresponds to the
     * {@code post_logout_redirect_uris} client metadata field.
     *
     * @return The logout redirection URIs, {@code null} if not specified.
     */
    public Set<URI> getPostLogoutRedirectionURIs() {

        return postLogoutRedirectURIs;
    }


    /**
     * Sets the post logout redirection URIs. Corresponds to the
     * {@code post_logout_redirect_uris} client metadata field.
     *
     * @param logoutURIs The logout redirection URIs, {@code null} if not
     *                   specified.
     */
    public void setPostLogoutRedirectionURIs(Set<URI> logoutURIs) {

        postLogoutRedirectURIs = logoutURIs;
    }


    /**
     * Gets the front-channel logout URI. Corresponds to the
     * {@code frontchannel_logout_uri} client metadata field.
     *
     * @return The front-channel logout URI, {@code null} if not specified.
     */
    public URI getFrontChannelLogoutURI() {

        return frontChannelLogoutURI;
    }


    /**
     * Sets the front-channel logout URI. Corresponds to the
     * {@code frontchannel_logout_uri} client metadata field.
     *
     * @param frontChannelLogoutURI The front-channel logout URI,
     *                              {@code null} if not specified.
     */
    public void setFrontChannelLogoutURI(URI frontChannelLogoutURI) {

        this.frontChannelLogoutURI = frontChannelLogoutURI;
    }


    /**
     * Gets the requirement for a session identifier on front-channel
     * logout. Corresponds to
     * the {@code frontchannel_logout_session_required} client metadata
     * field.
     *
     * @return {@code true} if a session identifier is required, else
     * {@code false}.
     */
    public boolean requiresFrontChannelLogoutSession() {

        return frontChannelLogoutSessionRequired;
    }


    /**
     * Sets the requirement for a session identifier on front-channel
     * logout. Corresponds to
     * the {@code frontchannel_logout_session_required} client metadata
     * field.
     *
     * @param requiresSession {@code true} if a session identifier is
     *                        required, else {@code false}.
     */
    public void requiresFrontChannelLogoutSession(boolean requiresSession) {

        frontChannelLogoutSessionRequired = requiresSession;
    }


    /**
     * Gets the back-channel logout URI. Corresponds to the
     * {@code backchannel_logout_uri} client metadata field.
     *
     * @return The back-channel logout URI, {@code null} if not specified.
     */
    public URI getBackChannelLogoutURI() {

        return backChannelLogoutURI;
    }


    /**
     * Sets the back-channel logout URI. Corresponds to the
     * {@code backchannel_logout_uri} client metadata field.
     *
     * @param backChannelLogoutURI The back-channel logout URI,
     *                             {@code null} if not specified.
     */
    public void setBackChannelLogoutURI(URI backChannelLogoutURI) {

        this.backChannelLogoutURI = backChannelLogoutURI;
    }


    /**
     * Gets the requirement for a session identifier on back-channel
     * logout. Corresponds to
     * the {@code backchannel_logout_session_required} client metadata
     * field.
     *
     * @return {@code true} if a session identifier is required, else
     * {@code false}.
     */
    public boolean requiresBackChannelLogoutSession() {

        return backChannelLogoutSessionRequired;
    }


    /**
     * Sets the requirement for a session identifier on back-channel
     * logout. Corresponds to
     * the {@code backchannel_logout_session_required} client metadata
     * field.
     *
     * @param requiresSession {@code true} if a session identifier is
     *                        required, else {@code false}.
     */
    public void requiresBackChannelLogoutSession(boolean requiresSession) {

        backChannelLogoutSessionRequired = requiresSession;
    }


    /**
     * Applies the client metadata defaults where no values have been
     * specified.
     *
     * <ul>
     *     <li>The response types default to {@code ["code"]}.
     *     <li>The grant types default to {@code "authorization_code".}
     *     <li>The client authentication method defaults to
     *         "client_secret_basic".
     *     <li>The application type defaults to
     *         {@link ApplicationType#WEB}.
     *     <li>The ID token JWS algorithm defaults to "RS256".
     * </ul>
     */
    @Override
    public void applyDefaults() {

        super.applyDefaults();

        if (applicationType == null) {
            applicationType = ApplicationType.WEB;
        }

        if (idTokenJWSAlg == null) {
            idTokenJWSAlg = JWSAlgorithm.RS256;
        }
    }


    @Override
    public JsonObjectBuilder toJSONObject(boolean includeCustomFields) {

        JsonObjectBuilder result = super.toJSONObject(includeCustomFields);

        result.addAll(Json.createObjectBuilder(getCustomFields()));

        if (applicationType != null) {
            result.add("application_type", applicationType.toString());
        }

        if (subjectType != null) {
            result.add("subject_type", subjectType.toString());
        }


        if (sectorIDURI != null) {
            result.add("sector_identifier_uri", sectorIDURI.toString());
        }


        if (idTokenJWSAlg != null) {
            result.add("id_token_signed_response_alg", idTokenJWSAlg.getName());
        }


        if (idTokenJWEAlg != null) {
            result.add("id_token_encrypted_response_alg", idTokenJWEAlg.getName());
        }


        if (idTokenJWEEnc != null) {
            result.add("id_token_encrypted_response_enc", idTokenJWEEnc.getName());
        }


        if (userInfoJWSAlg != null) {
            result.add("userinfo_signed_response_alg", userInfoJWSAlg.getName());
        }


        if (userInfoJWEAlg != null) {
            result.add("userinfo_encrypted_response_alg", userInfoJWEAlg.getName());
        }


        if (userInfoJWEEnc != null) {
            result.add("userinfo_encrypted_response_enc", userInfoJWEEnc.getName());
        }


        if (defaultMaxAge > 0) {
            result.add("default_max_age", defaultMaxAge);
        }


        if (requiresAuthTime()) {
            result.add("require_auth_time", requiresAuthTime);
        }


        if (defaultACRs != null) {

            result.add("default_acr_values", JSONArrayUtils.asJsonArray(defaultACRs));
        }


        if (initiateLoginURI != null) {
            result.add("initiate_login_uri", initiateLoginURI.toString());
        }


        if (postLogoutRedirectURIs != null) {

            result.add("post_logout_redirect_uris", JSONArrayUtils.URIsasJsonArray(postLogoutRedirectURIs));
        }

        if (frontChannelLogoutURI != null) {
            result.add("frontchannel_logout_uri", frontChannelLogoutURI.toString());
            result.add("frontchannel_logout_session_required", frontChannelLogoutSessionRequired);
        }

        if (backChannelLogoutURI != null) {
            result.add("backchannel_logout_uri", backChannelLogoutURI.toString());
            result.add("backchannel_logout_session_required", backChannelLogoutSessionRequired);
        }

        return result;
    }


    /**
     * Parses an OpenID Connect client metadata instance from the specified
     * JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The OpenID Connect client metadata.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to an
     *                                  OpenID Connect client metadata instance.
     */
    public static OIDCClientMetadata parse(JsonObject jsonObject)
            throws OAuth2JSONParseException {

        ClientMetadata baseMetadata = ClientMetadata.parse(jsonObject);

        OIDCClientMetadata metadata = new OIDCClientMetadata(baseMetadata);

        // Parse the OIDC-specific fields from the custom OAuth 2.0 dyn
        // reg fields

        JsonObject oidcFields = baseMetadata.getCustomFields();

        JsonObjectBuilder customFieldsBuilder = Json.createObjectBuilder(oidcFields);

        try {
            if (jsonObject.get("application_type") != null) {
                try {
                    metadata.setApplicationType(JSONObjectUtils.getEnum(jsonObject, "application_type", ApplicationType.class));
                } catch (IncorrectJsonValueException e) {
                    ErrorObject errorObject = new ErrorObject(RegistrationError.INVALID_CLIENT_METADATA.getCode(), "Invalid client metadata field: Unexpected value of JSON object member with key \"application_type\"");
                    throw new OAuth2JSONParseException("Unexpected value of JSON object member with key \"application_type\"", errorObject);
                }
                customFieldsBuilder.remove("application_type");
            }

            if (jsonObject.get("subject_type") != null) {
                metadata.setSubjectType(JSONObjectUtils.getEnum(jsonObject, "subject_type", SubjectType.class));
                customFieldsBuilder.remove("subject_type");
            }

            if (jsonObject.get("sector_identifier_uri") != null) {
                metadata.setSectorIDURI(JSONObjectUtils.getURI(jsonObject, "sector_identifier_uri"));
                customFieldsBuilder.remove("sector_identifier_uri");
            }

            if (jsonObject.get("id_token_signed_response_alg") != null) {
                if (JSONObjectUtils.hasValue(jsonObject, "id_token_signed_response_alg")) {
                    metadata.setIDTokenJWSAlg(JWSAlgorithm.parse(
                            jsonObject.getString("id_token_signed_response_alg")));
                }

                customFieldsBuilder.remove("id_token_signed_response_alg");
            }

            if (jsonObject.get("id_token_encrypted_response_alg") != null) {
                if (JSONObjectUtils.hasValue(jsonObject, "id_token_encrypted_response_alg")) {
                    metadata.setIDTokenJWEAlg(JWEAlgorithm.parse(
                            jsonObject.getString("id_token_encrypted_response_alg")));
                }
                customFieldsBuilder.remove("id_token_encrypted_response_alg");
            }

            if (jsonObject.get("id_token_encrypted_response_enc") != null) {
                if (JSONObjectUtils.hasValue(jsonObject, "id_token_encrypted_response_enc")) {
                    metadata.setIDTokenJWEEnc(EncryptionMethod.parse(
                            jsonObject.getString("id_token_encrypted_response_enc")));
                }
                customFieldsBuilder.remove("id_token_encrypted_response_enc");
            }

            if (jsonObject.get("userinfo_signed_response_alg") != null) {
                if (JSONObjectUtils.hasValue(jsonObject, "userinfo_signed_response_alg")) {
                    metadata.setUserInfoJWSAlg(JWSAlgorithm.parse(
                            jsonObject.getString("userinfo_signed_response_alg")));
                }
                customFieldsBuilder.remove("userinfo_signed_response_alg");
            }

            if (jsonObject.get("userinfo_encrypted_response_alg") != null) {
                if (JSONObjectUtils.hasValue(jsonObject, "userinfo_encrypted_response_alg")) {
                    metadata.setUserInfoJWEAlg(JWEAlgorithm.parse(
                            jsonObject.getString("userinfo_encrypted_response_alg")));
                }
                customFieldsBuilder.remove("userinfo_encrypted_response_alg");
            }

            if (jsonObject.get("userinfo_encrypted_response_enc") != null) {
                if (JSONObjectUtils.hasValue(jsonObject, "userinfo_encrypted_response_enc")) {

                    metadata.setUserInfoJWEEnc(EncryptionMethod.parse(
                            jsonObject.getString("userinfo_encrypted_response_enc")));
                }
                customFieldsBuilder.remove("userinfo_encrypted_response_enc");
            }

            if (jsonObject.get("default_max_age") != null) {
                if (JSONObjectUtils.hasValue(jsonObject, "default_max_age")) {
                    metadata.setDefaultMaxAge(jsonObject.getInt("default_max_age"));
                }
                customFieldsBuilder.remove("default_max_age");
            }

            if (jsonObject.get("require_auth_time") != null) {
                if (JSONObjectUtils.hasValue(jsonObject, "require_auth_time")) {
                    metadata.requiresAuthTime(jsonObject.getBoolean("require_auth_time"));
                }
                customFieldsBuilder.remove("require_auth_time");
            }

            if (jsonObject.get("default_acr_values") != null) {
                if (JSONObjectUtils.hasValue(jsonObject, "default_acr_values")) {
                    List<ACR> acrValues = new LinkedList<>();

                    for (String acrString : JSONObjectUtils.getStringList(jsonObject, "default_acr_values")) {
                        acrValues.add(new ACR(acrString));
                    }

                    metadata.setDefaultACRs(acrValues);
                }

                customFieldsBuilder.remove("default_acr_values");
            }

            if (jsonObject.get("initiate_login_uri") != null) {
                if (JSONObjectUtils.hasValue(jsonObject, "initiate_login_uri")) {
                    metadata.setInitiateLoginURI(JSONObjectUtils.getURI(jsonObject, "initiate_login_uri"));
                }
                customFieldsBuilder.remove("initiate_login_uri");
            }

            if (jsonObject.get("post_logout_redirect_uris") != null) {

                if (JSONObjectUtils.hasValue(jsonObject, "post_logout_redirect_uris")) {
                    Set<URI> logoutURIs = new LinkedHashSet<>();

                    for (String uriString : JSONObjectUtils.getStringList(jsonObject, "post_logout_redirect_uris")) {

                        try {
                            logoutURIs.add(new URI(uriString));

                        } catch (URISyntaxException e) {

                            throw new OAuth2JSONParseException("Invalid \"post_logout_redirect_uris\" parameter");
                        }
                    }

                    metadata.setPostLogoutRedirectionURIs(logoutURIs);
                }
                customFieldsBuilder.remove("post_logout_redirect_uris");
            }

            if (jsonObject.get("frontchannel_logout_uri") != null) {

                if (JSONObjectUtils.hasValue(jsonObject, "frontchannel_logout_uri")) {
                    metadata.setFrontChannelLogoutURI(JSONObjectUtils.getURI(jsonObject, "frontchannel_logout_uri"));
                }
                customFieldsBuilder.remove("frontchannel_logout_uri");


                if (jsonObject.get("frontchannel_logout_session_required") != null) {
                    if (JSONObjectUtils.hasValue(jsonObject, "frontchannel_logout_session_required")) {
                        metadata.requiresFrontChannelLogoutSession(jsonObject.getBoolean("frontchannel_logout_session_required"));
                    }
                    customFieldsBuilder.remove("frontchannel_logout_session_required");
                }
            }


            if (jsonObject.get("backchannel_logout_uri") != null) {

                if (JSONObjectUtils.hasValue(jsonObject, "backchannel_logout_uri")) {
                    metadata.setBackChannelLogoutURI(JSONObjectUtils.getURI(jsonObject, "backchannel_logout_uri"));
                }
                customFieldsBuilder.remove("backchannel_logout_uri");

                if (jsonObject.get("backchannel_logout_session_required") != null) {
                    if (JSONObjectUtils.hasValue(jsonObject, "backchannel_logout_session_required")) {
                        metadata.requiresBackChannelLogoutSession(jsonObject.getBoolean("backchannel_logout_session_required"));
                    }
                    customFieldsBuilder.remove("backchannel_logout_session_required");
                }
            }


        } catch (OAuth2JSONParseException | ParseException e) {
            // Insert client_client_metadata error code so that it
            // can be reported back to the client if we have a
            // registration event
            throw new OAuth2JSONParseException(e.getMessage(), RegistrationError.INVALID_CLIENT_METADATA.appendDescription(": " + e.getMessage()), e.getCause());
        }

        // The remaining fields are custom

        metadata.setCustomFields(customFieldsBuilder.build());

        return metadata;
    }
}
