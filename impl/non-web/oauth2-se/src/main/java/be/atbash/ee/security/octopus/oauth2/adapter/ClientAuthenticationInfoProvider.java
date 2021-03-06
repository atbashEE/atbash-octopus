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
package be.atbash.ee.security.octopus.oauth2.adapter;

import be.atbash.ee.oauth2.sdk.AccessTokenResponse;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.TokenErrorResponse;
import be.atbash.ee.oauth2.sdk.TokenResponse;
import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationStrategy;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.PermissionJSONProvider;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.realm.AuthorizationInfoBuilder;
import be.atbash.ee.security.octopus.realm.SecurityDataProvider;
import be.atbash.ee.security.octopus.sso.client.ClientCustomization;
import be.atbash.ee.security.octopus.sso.client.OpenIdVariableClientData;
import be.atbash.ee.security.octopus.sso.client.SSOAuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.sso.client.config.OctopusSSOServerClientConfiguration;
import be.atbash.ee.security.octopus.sso.client.requestor.OctopusUserRequestor;
import be.atbash.ee.security.octopus.sso.client.requestor.PermissionRequestor;
import be.atbash.ee.security.octopus.sso.core.OctopusRetrievalException;
import be.atbash.ee.security.octopus.sso.core.rest.DefaultPrincipalUserInfoJSONProvider;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOTokenConverter;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URISyntaxException;
import java.util.List;
import java.util.ServiceLoader;

/**
 *
 */
public class ClientAuthenticationInfoProvider extends SecurityDataProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientAuthenticationInfoProvider.class.getName());

    private OctopusCoreConfiguration coreConfiguration;
    private OctopusSSOServerClientConfiguration configuration;
    private PermissionRequestor permissionRequestor;

    private void init() {
        if (coreConfiguration == null) {
            coreConfiguration = OctopusCoreConfiguration.getInstance();
            configuration = OctopusSSOServerClientConfiguration.getInstance();
            OctopusSSOServerClientConfiguration serverClientConfiguration = OctopusSSOServerClientConfiguration.getInstance();

            PermissionJSONProvider permissionJSONProvider = getPermissionJSONProvider();

            ClientCustomization clientCustomization = getClientCustomization();

            if (clientCustomization == null) {
                permissionRequestor = new PermissionRequestor(coreConfiguration, serverClientConfiguration, null, null, permissionJSONProvider);
            } else {
                permissionRequestor = new PermissionRequestor(coreConfiguration, serverClientConfiguration, clientCustomization, clientCustomization.getConfiguration(PermissionRequestor.class), permissionJSONProvider);
            }
        }
    }

    private ClientCustomization getClientCustomization() {
        ClientCustomization clientCustomization = null;
        ServiceLoader<ClientCustomization> clientCustomizations = ServiceLoader.load(ClientCustomization.class);

        for (ClientCustomization customization : clientCustomizations) {
            clientCustomization = customization;
            break;
        }
        return clientCustomization;
    }

    private PermissionJSONProvider getPermissionJSONProvider() {
        // Allow the developer to define a PermissionJSONProvider through the service mechanism
        PermissionJSONProvider permissionJSONProvider = null;

        ServiceLoader<PermissionJSONProvider> providers = ServiceLoader.load(PermissionJSONProvider.class);
        for (PermissionJSONProvider provider : providers) {
            permissionJSONProvider = provider;
            break;
        }

        if (permissionJSONProvider == null) {
            permissionJSONProvider = new PermissionJSONProvider();
        }
        return permissionJSONProvider;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        init();

        if (token instanceof UsernamePasswordToken) {
            // for the Java SE use case

            UsernamePasswordToken usernamePassword = (UsernamePasswordToken) token;
            TokenResponse tokenResponse = TokenRequestor.getInstance(coreConfiguration, configuration).getToken(usernamePassword);

            if (!tokenResponse.indicatesSuccess()) {
                TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
                // FIXME
                return null;
            }

            AccessTokenResponse accessTokenResponse = (AccessTokenResponse) tokenResponse;

            OctopusUserRequestor octopusUserRequestor = new OctopusUserRequestor(coreConfiguration, configuration, new OctopusSSOTokenConverter(),
                    new DefaultPrincipalUserInfoJSONProvider(), null);

            OpenIdVariableClientData clientData = new OpenIdVariableClientData();
            OctopusSSOToken octopusSSOToken;

            try {
                octopusSSOToken = octopusUserRequestor.getOctopusSSOToken(clientData, accessTokenResponse.getTokens().getBearerAccessToken());

            } catch (URISyntaxException | JOSEException | java.text.ParseException | OctopusRetrievalException | OAuth2JSONParseException e) {
                e.printStackTrace(); // FIXME
                return null;
            }

            octopusSSOToken.setLogoutHandlerAsRequired();
            return new SSOAuthenticationInfoBuilder(octopusSSOToken).getAuthenticationInfo();
        }

        return null;
    }

    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {
        init();

        UserPrincipal userPrincipal = principals.getPrimaryPrincipal();

        Object token = userPrincipal.getUserInfo(OctopusConstants.INFO_KEY_TOKEN);
        if (!(token instanceof OctopusSSOToken)) {
            throw new AtbashUnexpectedException("UserPrincipal should be based on OctopusSSOToken. Did you use fakeLogin Module and forget to define Permissions for the fake user?");
        }

        OctopusSSOToken ssoUser = (OctopusSSOToken) token;
        String realToken = ssoUser.getAccessToken();

        if (coreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            LOGGER.info(String.format("(SSO Client) Retrieving authorization info for user %s from Octopus SSO Server", ssoUser.getFullName()));
        }

        List<NamedDomainPermission> domainPermissions = permissionRequestor.retrieveUserPermissions(realToken);

        AuthorizationInfoBuilder infoBuilder = new AuthorizationInfoBuilder();
        infoBuilder.addPermissions(domainPermissions);

        return infoBuilder.build();
    }

    @Override
    public AuthenticationStrategy getAuthenticationStrategy() {
        return AuthenticationStrategy.SUFFICIENT;
    }
}
