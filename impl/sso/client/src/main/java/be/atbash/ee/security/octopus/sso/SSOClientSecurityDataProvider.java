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
package be.atbash.ee.security.octopus.sso;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.PermissionJSONProvider;
import be.atbash.ee.security.octopus.authz.permission.StringPermissionLookup;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.realm.AuthorizationInfoBuilder;
import be.atbash.ee.security.octopus.realm.SecurityDataProvider;
import be.atbash.ee.security.octopus.sso.client.SSOAuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.sso.client.ClientCustomization;
import be.atbash.ee.security.octopus.sso.client.config.OctopusSSOServerClientConfiguration;
import be.atbash.ee.security.octopus.sso.client.requestor.PermissionRequestor;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.util.CDIUtils;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import java.util.List;

@ApplicationScoped
public class SSOClientSecurityDataProvider extends SecurityDataProvider {

    @Inject
    private Logger logger;

    @Inject
    private OctopusCoreConfiguration coreConfiguration;

    @Inject
    private OctopusSSOServerClientConfiguration serverClientConfiguration;

    private PermissionRequestor permissionRequestor;

    @PostConstruct
    public void init() {
        // The PermissionJSONProvider is located in a JAR With CDI support.
        // Developer must have to opportunity to define a custom version.
        // So first look at CDI class. If not found, use the default.
        PermissionJSONProvider permissionJSONProvider = CDIUtils.retrieveOptionalInstance(PermissionJSONProvider.class);
        if (permissionJSONProvider == null) {
            permissionJSONProvider = new PermissionJSONProvider();
        }

        ClientCustomization clientCustomization = CDIUtils.retrieveOptionalInstance(ClientCustomization.class);
        if (clientCustomization == null) {
            permissionRequestor = new PermissionRequestor(coreConfiguration, serverClientConfiguration, null, null, permissionJSONProvider);
        } else {
            permissionRequestor = new PermissionRequestor(coreConfiguration, serverClientConfiguration, clientCustomization, clientCustomization.getConfiguration(PermissionRequestor.class), permissionJSONProvider);
        }

    }

    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof OctopusSSOToken) {
            OctopusSSOToken user = (OctopusSSOToken) token;

            return new SSOAuthenticationInfoBuilder(user).getAuthenticationInfo();
        }

        return null;
    }

    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        UserPrincipal userPrincipal = principals.getPrimaryPrincipal();

        Object token = userPrincipal.getUserInfo(OctopusConstants.INFO_KEY_TOKEN);
        AuthorizationInfoBuilder infoBuilder = new AuthorizationInfoBuilder();

        if (!(token instanceof OctopusSSOToken)) {
            throw new AtbashUnexpectedException("UserPrincipal should be based OctopusSSOToken. Did you use fakeLogin Module and forget to define Permissions for the fake user?");
        }
        OctopusSSOToken ssoUser = (OctopusSSOToken) token;

        String realToken = ssoUser.getAccessToken();

        if (coreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("(SSO Client) Retrieving authorization info for user %s from Octopus SSO Server", ssoUser.getFullName()));
        }

        List<NamedDomainPermission> domainPermissions = permissionRequestor.retrieveUserPermissions(realToken);
        infoBuilder.addPermissions(domainPermissions);

        return infoBuilder.build();
    }


    @ApplicationScoped
    @Produces
    public StringPermissionLookup createLookup() {

        if (coreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("(SSO Client) Retrieving all permissions for application %s", serverClientConfiguration.getSSOApplication()));
        }

        if (StringUtils.isEmpty(serverClientConfiguration.getSSOApplication())) {
            // No SSO.application defined in config so we do not need to retrieve the Lookup.
            return new StringPermissionLookup();
        }

        List<NamedDomainPermission> permissions = permissionRequestor.retrieveAllPermissions();

        if (!permissions.isEmpty()) {
            return new StringPermissionLookup(permissions);
        }

        if (isFakeLoginActive()) {
            // FIXME
            /*
            FakePermissionProvider fakePermissionProvider = BeanProvider.getContextualReference(FakePermissionProvider.class, true);
            if (fakePermissionProvider != null) {
                return new StringPermissionLookup(fakePermissionProvider.getApplicationPermissions());
            }

             */
        }
        throw new ConfigurationException("Unable to create StringPermissionLookup, See ??? for solutions");

    }

    private boolean isFakeLoginActive() {
        boolean result = false;
        /*
        try {
            // FIXME
            Class.forName("????.FakeAuthenticationServlet");
            result = true;
        } catch (ClassNotFoundException e) {
            ; // Nothing to do, fakeLogin Module isn't with classpath.
        }

         */
        return result;
    }


}
