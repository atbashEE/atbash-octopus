/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.realm;

import be.atbash.ee.security.octopus.authc.*;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationInfoProviderHandler;
import be.atbash.ee.security.octopus.authz.TokenBasedAuthorizationInfoProvider;
import be.atbash.ee.security.octopus.authz.init.RoleMapperProviderLoader;
import be.atbash.ee.security.octopus.mgt.authz.LookupProviderLoader;
import be.atbash.ee.security.octopus.realm.mgmt.LookupProvider;
import be.atbash.ee.security.octopus.realm.mgmt.RoleMapperProvider;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.systemaccount.SystemAccountAuthenticationToken;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.AuthorizationToken;
import be.atbash.ee.security.octopus.util.onlyduring.TemporaryAuthorizationContextManager;
import be.atbash.util.reflection.ClassUtils;

/**
 *
 */
public class OctopusOfflineRealm extends AuthorizingRealm {

    private static OctopusOfflineRealm INSTANCE;

    private AuthenticationInfoProviderHandler authenticationInfoProviderHandler = new AuthenticationInfoProviderHandler();

    private AuthorizationInfoProviderHandler authorizationInfoProviderHandler;

    private OctopusOfflineRealm() {
    }

    private void initDependencies() {
        LookupProvider<? extends Enum> lookupProvider = new LookupProviderLoader().loadLookupProvider();
        RoleMapperProvider<? extends Enum> roleMapperProvider = new RoleMapperProviderLoader().loadRoleMapperProvider();
        initDependencies(lookupProvider, roleMapperProvider);
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        prepareAuthorizationInfoProviderHandler();

        class Guard {
        }
        TemporaryAuthorizationContextManager.startInAuthorization(Guard.class);
        AuthorizationInfo authorizationInfo;
        try {
            /*
            FIXME OctopusWebSecurityContext.isSystemAccount needs to work through the AuthorizationInfoProvider
            if (OctopusWebSecurityContext.isSystemAccount(primaryPrincipal)) {
                // No permissions or roles, use @SystemAccount
                authorizationInfo = new SimpleAuthorizationInfo();
            } else {
                //authorizationInfo = securityDataProvider.getAuthorizationInfo(principals);
            }
            */
            authorizationInfo = authorizationInfoProviderHandler.retrieveAuthorizationInfo(principals);
        } finally {
            TemporaryAuthorizationContextManager.stopInAuthorization();
        }
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        AuthenticationInfo authenticationInfo = null;

        if (token instanceof SystemAccountAuthenticationToken) {
            // TODO Use the authenticationInfoProvider for this.
            //authenticationInfo = new SimpleAuthenticationInfo(token.getPrincipal(), ""); // FIXME custom constructor
        } else {
            if (!(token instanceof IncorrectDataToken)) {
                class Guard {
                }
                TemporaryAuthorizationContextManager.startInAuthentication(Guard.class);
                try {

                    authenticationInfo = authenticationInfoProviderHandler.retrieveAuthenticationInfo(token);
                    if (authenticationInfo == null) {
                        String msg = String.format("Realm was unable to find account data for the " +
                                "submitted AuthenticationToken [%s].", token);
                        throw new UnknownAccountException(msg);

                    }
                    verifyHashEncoding(authenticationInfo);
                } finally {
                    // Even in the case of an exception (access not allowed) we need to reset this flag
                    TemporaryAuthorizationContextManager.stopInAuthentication();
                }
            }
        }

        return authenticationInfo;
    }

    private AuthorizationToken getAuthorizationToken(AuthenticationToken token, AuthenticationInfo authenticationInfo) {
        AuthorizationToken result = null;

        if (authenticationInfo != null && token instanceof AuthorizationToken) {
            result = (AuthorizationToken) token;
        }

        if (authenticationInfo != null && authenticationInfo.getValidatedToken() instanceof AuthorizationToken) {
            result = (AuthorizationToken) authenticationInfo.getValidatedToken();
        }

        return result;
    }

    private void prepareAuthorizationInfoProviderHandler() {
        if (authorizationInfoProviderHandler == null) {
            authorizationInfoProviderHandler = new AuthorizationInfoProviderHandler();
        }
    }

    protected Object getAuthorizationCacheKey(PrincipalCollection principals) {
        return principals.getPrimaryPrincipal();
    }

    protected boolean isAuthenticationCachingEnabled(AuthenticationToken token, AuthenticationInfo info) {
        boolean result = false;  // For systemAccounts, no caching
        if (!(token instanceof SystemAccountAuthenticationToken)) {
            result = isAuthenticationCachingEnabled();
        }
        return result;
    }

    @Override
    protected void assertCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) throws AuthenticationException {
        class Guard {
        }
        TemporaryAuthorizationContextManager.startInSystemAccount(Guard.class);
        try {
            super.assertCredentialsMatch(token, info);
        } finally {
            TemporaryAuthorizationContextManager.stopInSystemAccount();
        }
    }

    @Override
    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        //assertRealmsConfigured();  TODO Needed ??
        //Collection<Realm> realms = getRealms();

        AuthenticationInfo result = getAuthenticationInfo(authenticationToken);
        AuthorizationToken authorizationToken = getAuthorizationToken(authenticationToken, result);
        if (authorizationToken != null) {
            TokenBasedAuthorizationInfoProvider authorizationInfoProvider = ClassUtils.newInstance(authorizationToken.authorizationProviderClass());
            AuthorizationInfo authorizationInfo = authorizationInfoProvider.getAuthorizationInfo(authorizationToken);

            cacheAuthorizationInfo(result.getPrincipals(), authorizationInfo);
        }
        return result;

    }

    private void checkAuthorizationInfoMarkers() {
        // FIXME
        //authorizationInfoRequired = !BeanProvider.getContextualReferences(PrincipalAuthorizationInfoAvailibility.class, true).isEmpty();
    }

    private void configureListeners() {
        /* FIXME
        AuthenticationListener listener = BeanProvider.getContextualReference(OctopusAuthenticationListener.class);
        getAuthenticationListeners().add(listener);
*/
    }

    public static OctopusOfflineRealm getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new OctopusOfflineRealm();
            INSTANCE.initDependencies();
            INSTANCE.configureListeners();
            INSTANCE.checkAuthorizationInfoMarkers();
        }
        return INSTANCE;
    }
}
