/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.sso.server.endpoint;

import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.openid.connect.sdk.claims.IDTokenClaimsSet;
import be.atbash.ee.openid.connect.sdk.claims.UserInfo;
import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.WebConstants;
import be.atbash.ee.security.octopus.authz.annotation.RequiresUser;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.PermissionJSONProvider;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.nimbus.jose.CustomParameterNameException;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.sso.core.rest.DefaultPrincipalUserInfoJSONProvider;
import be.atbash.ee.security.octopus.sso.core.rest.PrincipalUserInfoJSONProvider;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOTokenConverter;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.TimeUtil;
import be.atbash.ee.security.octopus.util.URLUtil;
import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.client.ClientInfoRetriever;
import be.atbash.ee.security.sso.server.config.OctopusSSOServerConfiguration;
import be.atbash.ee.security.sso.server.config.UserEndpointEncoding;
import be.atbash.ee.security.sso.server.store.OIDCStoreData;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.util.CDIUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.annotation.security.PermitAll;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.io.Serializable;
import java.util.*;


/**
 *
 */
@Path("/octopus/sso")
@Singleton
public class OctopusSSOEndpoint {

    private static final List<String> KEYS = Arrays.asList(OctopusConstants.EMAIL, OctopusConstants.TOKEN, "rememberMe");

    private Logger logger = LoggerFactory.getLogger(OctopusSSOEndpoint.class);

    @Inject
    private OctopusCoreConfiguration coreConfiguration;

    @Inject
    private OctopusSSOServerConfiguration ssoServerConfiguration;

    @Inject
    private SSOPermissionProvider ssoPermissionProvider;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @Inject
    private OctopusSSOTokenConverter octopusSSOTokenConverter;

    @Inject
    private TimeUtil timeUtil;

    @Inject
    private URLUtil urlUtil;

    private PrincipalUserInfoJSONProvider userInfoJSONProvider;

    private PermissionJSONProvider permissionJSONProvider;

    private AccessTokenTransformer accessTokenTransformer;

    private UserEndpointDataTransformer userEndpointDataTransformer;

    @PostConstruct
    public void init() {
        // The PermissionJSONProvider is located in a JAR With CDI support.
        // Developer must have to opportunity to define a custom version.
        // So first look at CDI class. If not found, use the default.

        permissionJSONProvider = CDIUtils.retrieveOptionalInstance(PermissionJSONProvider.class);
        if (permissionJSONProvider == null) {
            permissionJSONProvider = new PermissionJSONProvider();
        }

        userInfoJSONProvider = CDIUtils.retrieveOptionalInstance(PrincipalUserInfoJSONProvider.class);
        if (userInfoJSONProvider == null) {
            userInfoJSONProvider = new DefaultPrincipalUserInfoJSONProvider();
        }

        accessTokenTransformer = CDIUtils.retrieveOptionalInstance(AccessTokenTransformer.class);
        userEndpointDataTransformer = CDIUtils.retrieveOptionalInstance(UserEndpointDataTransformer.class);
    }

    @Path("/user")
    @POST
    @RequiresUser
    public Response getUserInfoPost(@HeaderParam(OctopusConstants.AUTHORIZATION_HEADER) String authorizationHeader, @Context UriInfo uriDetails) {
        return getUserInfo(authorizationHeader, uriDetails);
    }

    @Path("/user")
    @GET
    @RequiresUser
    public Response getUserInfo(@HeaderParam(OctopusConstants.AUTHORIZATION_HEADER) String authorizationHeader, @Context UriInfo uriDetails) {

        UserPrincipal userPrincipal = getUserPrincipal();
        //When scope contains octopus -> always signed or encrypted. and not JSON by default !!!
        showDebugInfo(userPrincipal);

        String accessToken = getAccessToken(authorizationHeader);
        //

        // Special custom requirements to the accessToken like signed tokens
        if (accessTokenTransformer != null) {
            accessToken = accessTokenTransformer.transformAccessToken(accessToken);
        }

        OIDCStoreData oidcStoreData = tokenStore.getOIDCDataByAccessToken(accessToken);
        if (oidcStoreData == null) {
            // TODO is this possible? ssoFilter makes sure that the access token is allowed and valid.
            // Could we have an issue here with the tokenStore (and clustered environments)?
            throw new AtbashUnexpectedException("OIDCStoreData is null for accessToken");
        }
        IDTokenClaimsSet idTokenClaimsSet = oidcStoreData.getIdTokenClaimsSet();

        JWTClaimsSet jwtClaimsSet;
        try {
            if (idTokenClaimsSet == null) {
                // There was no scope openid specified. But for convenience we define a minimal response
                JsonObjectBuilder json = Json.createObjectBuilder();
                json.add(UserInfo.SUB_CLAIM_NAME, userPrincipal.getUserName());

                json.add("iss", urlUtil.determineRoot(uriDetails.getBaseUri()));

                Date iat = new Date();
                Date exp = timeUtil.addSecondsToDate(ssoServerConfiguration.getSSOAccessTokenTimeToLive(), iat); // TODO Verify how we handle expiration when multiple clients are using the server

                json.add("exp", exp.getTime());

                jwtClaimsSet = JWTClaimsSet.parse(json.build());
            } else {
                jwtClaimsSet = idTokenClaimsSet.toJWTClaimsSet();
            }
        } catch (OAuth2JSONParseException e) {
            throw new AtbashUnexpectedException(e);
        }

        UserEndpointEncoding endpointEncoding = ssoServerConfiguration.getUserEndpointEncoding();

        if (endpointEncoding == UserEndpointEncoding.JWE) {
            throw new ConfigurationException("SSO server user endpoint coding JWE is not yet suported");
            // TODO Support for JWE
        }

        UserInfo userInfo = octopusSSOTokenConverter.fromIdToken(jwtClaimsSet);

        Scope scope = oidcStoreData.getAccessToken().getScope();
        if (scope != null && scope.contains("octopus")) {

            userInfo.putAll(octopusSSOTokenConverter.asClaims(userPrincipal, userInfoJSONProvider));

            endpointEncoding = UserEndpointEncoding.JWS;
        }

        if (scope != null && scope.contains("email")) {

            userInfo.setEmailAddress(userPrincipal.getEmail());
        }

        if (scope != null && scope.contains("userinfo")) {

            Map<String, Object> filteredInfo = new HashMap<>();
            for (Map.Entry<String, Serializable> entry : userPrincipal.getInfo().entrySet()) {
                if (!KEYS.contains(entry.getKey())) {
                    filteredInfo.put(entry.getKey(), entry.getValue());
                }
            }
            userInfo.putAll(filteredInfo);
        }

        if (userEndpointDataTransformer != null) {
            userInfo = userEndpointDataTransformer.transform(userInfo, userPrincipal, scope);
        }

        Response.ResponseBuilder builder = Response.status(Response.Status.OK);

        // Is this endpoint specified in OpenIdConnect and is NONE allowed?
        if (endpointEncoding == UserEndpointEncoding.NONE) {
            builder.type(CommonContentTypes.APPLICATION_JSON.toString());
            builder.entity(userInfo.toJSONObject().build().toString());
        }

        if (endpointEncoding == UserEndpointEncoding.JWS) {
            buildResponsePayload(builder, uriDetails, oidcStoreData, userInfo);
        }

        return builder.build();

    }

    private UserPrincipal getUserPrincipal() {
        WebSubject subject = SecurityUtils.getSubject();
        return subject.getPrincipal();
    }

    private void buildResponsePayload(Response.ResponseBuilder builder, UriInfo uriDetails, OIDCStoreData oidcStoreData, UserInfo userInfo) {
        builder.type(CommonContentTypes.APPLICATION_JWT.toString());

        JWSHeader header;
        try {
            header = new JWSHeader(JWSAlgorithm.HS256);
        } catch (CustomParameterNameException e) {
            throw new AtbashUnexpectedException(e);
        }

        JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder();

        claimSetBuilder.issuer(uriDetails.getRequestUri().toASCIIString());
        claimSetBuilder.expirationTime(timeUtil.addSecondsToDate(2, new Date()));
        // Spec defines that we need also aud, but this is already set from idTokenClaimSet

        JsonObject jsonObject = userInfo.toJSONObject().build();
        for (Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {
            if ("aud".equals(entry.getKey())) {
                // due to octopusSSOTokenConverter.fromIdToken(jwtClaimsSet); earlier, there was a conversion from jwtClaimsSet to JSonObject
                // Which converted the Audience List to a single String.  If we don't put it in the correct type again, the new SignedJWT 3 statements further on
                // Will fail on the audience and leave it out from the SignedJWT.
                // FIXME Is this always the case (so is it possible to get a List here or not?)
                // FIXME simplify the joggling between String and Array for aud.
                claimSetBuilder.claim(entry.getKey(), Collections.singletonList(JSONObjectUtils.getJsonValueAsObject(entry.getValue())));
            } else {
                claimSetBuilder.claim(entry.getKey(), JSONObjectUtils.getJsonValueAsObject(entry.getValue()));
            }
        }

        SignedJWT signedJWT = new SignedJWT(header, claimSetBuilder.build());

        // Apply the HMAC
        ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(oidcStoreData.getClientId().getValue());
        try {
            signedJWT.sign(new MACSigner(clientInfo.getIdTokenSecretByte()));
        } catch (JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }

        builder.entity(signedJWT.serialize());
    }

    private String getAccessToken(String authorizationHeader) {
        return authorizationHeader.split(" ")[1];
    }

    private void showDebugInfo(UserPrincipal user) {

        if (coreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("Returning user info for  %s (cookie token = %s)", user.getName(), user.getUserInfo(WebConstants.SSO_COOKIE_TOKEN)));
        }
    }

    @Path("/user/permissions/{applicationName}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresUser
    public Map<String, String> getUserPermissions(@PathParam("applicationName") String application, @Context HttpServletRequest httpServletRequest) {
        UserPrincipal userPrincipal = getUserPrincipal();

        if (coreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("(SSO Server) Return all permissions for user %s within application %s", userPrincipal.getUserName(), application));
        }

        Scope scope = (Scope) httpServletRequest.getAttribute(Scope.class.getName());
        if (scope != null && (scope.contains("octopus") || scope.contains(ssoServerConfiguration.getScopeForPermissions()))) {
            return fromPermissionsToMap(ssoPermissionProvider.getPermissionsForUserInApplication(application, userPrincipal));
        } else {
            return null;
        }
    }

    @Path("/permissions/{applicationName}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @PermitAll
    public Map<String, String> getPermissions(@PathParam("applicationName") String application) {
        if (coreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("(SSO Server) Return all permissions for application %s", application));
        }
        // Return the list of all permissions !!!
        // For the moment anon access!!
        return fromPermissionsToMap(ssoPermissionProvider.getPermissionsForApplication(application));
    }

    private Map<String, String> fromPermissionsToMap(List<NamedDomainPermission> permissions) {
        Map<String, String> result = new HashMap<>();
        for (NamedDomainPermission permission : permissions) {
            result.put(permission.getName(), permissionJSONProvider.writeValue(permission));
        }
        return result;
    }
}
