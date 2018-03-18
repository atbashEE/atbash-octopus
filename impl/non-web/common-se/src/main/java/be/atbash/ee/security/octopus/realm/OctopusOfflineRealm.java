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
import be.atbash.ee.security.octopus.mgt.authz.LookupProviderLoader;
import be.atbash.ee.security.octopus.realm.mgmt.LookupProvider;
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

    private boolean listenerConfigured = false;  // FIXME Needed ?

    private boolean authorizationInfoRequired = false;

    private AuthenticationInfoProviderHandler authenticationInfoProviderHandler;

    private AuthorizationInfoProviderHandler authorizationInfoProviderHandler;

    public void initDependencies() {
        LookupProvider<? extends Enum> lookupProvider = new LookupProviderLoader().loadLookupProvider();
        initDependencies(lookupProvider);
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
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
            // FIXME Do we need this doGetAuthorizationInfo for offlineRealm. Isn't it always the case
            // that AuthorizationToken concept is used.
            authorizationInfo = null;
        } finally {
            TemporaryAuthorizationContextManager.stopInAuthorization();
        }
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        prepareAuthenticationInfoProviderHandler();

        AuthenticationInfo authenticationInfo = null;

        if (token instanceof SystemAccountAuthenticationToken) {
            // TODO Use the authenticationInfoProvider for this.
            authenticationInfo = new SimpleAuthenticationInfo(token.getPrincipal(), ""); // FIXME custom constructor
        } else {
            if (!(token instanceof IncorrectDataToken)) {
                class Guard {
                }
                TemporaryAuthorizationContextManager.startInAuthentication(Guard.class);
                try {

                    authenticationInfo = authenticationInfoProviderHandler.retrieveAuthenticationInfo(token);
                    verifyHashEncoding(authenticationInfo);
                } finally {
                    // Even in the case of an exception (access not allowed) we need to reset this flag
                    TemporaryAuthorizationContextManager.stopInAuthentication();
                }
            }
        }

        if (authenticationInfo != null && token instanceof AuthorizationToken) {
            AuthorizationToken authorizationToken = (AuthorizationToken) token;

            TokenBasedAuthorizationInfoProvider authorizationInfoProvider = ClassUtils.newInstance(authorizationToken.authorizationProviderClass());
            AuthorizationInfo authorizationInfo = authorizationInfoProvider.getAuthorizationInfo(authorizationToken);

            cacheAuthorizationInfo(authenticationInfo.getPrincipals(), authorizationInfo);
        }

        return authenticationInfo;
    }

    private void prepareAuthenticationInfoProviderHandler() {
        if (authenticationInfoProviderHandler == null) {
            authenticationInfoProviderHandler = new AuthenticationInfoProviderHandler();

        }

    }

    private void prepareAuthorizationInfoProviderHandler() {
        // FIXME Not used but should!!
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
        if (!listenerConfigured) {
            configureListeners();
            checkAuthorizationInfoMarkers();
        }
        //assertRealmsConfigured();  TODO Needed ??
        //Collection<Realm> realms = getRealms();

        return getAuthenticationInfo(authenticationToken);

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
        listenerConfigured = true;
    }

}
