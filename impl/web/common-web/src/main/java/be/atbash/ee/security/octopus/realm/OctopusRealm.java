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
package be.atbash.ee.security.octopus.realm;

import be.atbash.ee.security.octopus.authc.*;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationInfoProviderHandler;
import be.atbash.ee.security.octopus.authz.SimpleAuthorizationInfo;
import be.atbash.ee.security.octopus.authz.TokenBasedAuthorizationInfoProvider;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.systemaccount.internal.SystemAccountAuthenticationToken;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.AuthorizationToken;
import be.atbash.ee.security.octopus.util.onlyduring.TemporaryAuthorizationContextManager;
import be.atbash.util.CDIUtils;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class OctopusRealm extends AuthorizingRealm {

    private boolean listenerConfigured = false;

    @Inject
    private AuthenticationInfoProviderHandler authenticationInfoProviderHandler;

    @Inject
    private AuthorizationInfoProviderHandler authorizationInfoProviderHandler;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        class Guard {
        }
        TemporaryAuthorizationContextManager.startInAuthorization(Guard.class);
        AuthorizationInfo authorizationInfo;
        try {
            UserPrincipal userPrincipal = principals.getPrimaryPrincipal();

            if (userPrincipal.isSystemAccount()) {
                authorizationInfo = new SimpleAuthorizationInfo();  // TODO
            } else {
                // FIXME OctopusDefinedAuthorizationInfo usage !!
                authorizationInfo = authorizationInfoProviderHandler.retrieveAuthorizationInfo(principals);
            }
        } finally {

            TemporaryAuthorizationContextManager.stopInAuthorization();
        }
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo authenticationInfo = null;

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

        // FIXME implement the be.c4j.ee.security.realm.OctopusRealmAuthenticator#doSingleRealmAuthentication() logic
        return authenticationInfo;
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
        if (!listenerConfigured) {  // FIXME listenerConfigured never set to true
            configureListeners();
            checkAuthorizationInfoMarkers();
        }
        //assertRealmsConfigured();  TODO Needed ??
        //Collection<Realm> realms = getRealms();

        if (authenticationToken instanceof IncorrectDataToken) {
            throw new InvalidCredentialsException(((IncorrectDataToken) authenticationToken).getMessage());
        }

        AuthenticationInfo authenticationInfo = getAuthenticationInfo(authenticationToken);

        AuthorizationToken authorizationToken = getAuthorizationToken(authenticationToken, authenticationInfo);
        // FIXME Indicate case where we need to define authorizationInfo immediately
        if (authorizationToken != null) {

            // FIXME Check if the authorizationToken.authorizationProviderClass() is defined as CDI bean
            TokenBasedAuthorizationInfoProvider authorizationInfoProvider = CDIUtils.retrieveInstance(authorizationToken.authorizationProviderClass());
            AuthorizationInfo authorizationInfo = authorizationInfoProvider.getAuthorizationInfo(authorizationToken);

            // FIXME Additional authorizationInfoProviders
            cacheAuthorizationInfo(authenticationInfo.getPrincipals(), authorizationInfo);
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

    private void checkAuthorizationInfoMarkers() {
        // FIXME But can't be realm general anymore, needs to be based for the token.
        //authorizationInfoRequired = !BeanProvider.getContextualReferences(PrincipalAuthorizationInfoAvailibility.class, true).isEmpty();
    }

    private void configureListeners() {

        List<AuthenticationListener> authenticationListeners = CDIUtils.retrieveInstances(AuthenticationListener.class);
        setAuthenticationListeners(authenticationListeners);

    }
}
