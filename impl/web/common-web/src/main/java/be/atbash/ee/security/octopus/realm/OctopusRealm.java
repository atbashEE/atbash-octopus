/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.authz.SimpleAuthorizationInfo;
import be.atbash.ee.security.octopus.codec.Base64;
import be.atbash.ee.security.octopus.codec.CodecUtil;
import be.atbash.ee.security.octopus.codec.Hex;
import be.atbash.ee.security.octopus.config.OctopusWebConfiguration;
import be.atbash.ee.security.octopus.context.OctopusWebSecurityContext;
import be.atbash.ee.security.octopus.context.WebThreadContext;
import be.atbash.ee.security.octopus.crypto.hash.HashEncoding;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.systemaccount.SystemAccountAuthenticationToken;
import be.atbash.ee.security.octopus.token.AuthenticationToken;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class OctopusRealm extends AuthorizingRealm {

    public static final String IN_AUTHENTICATION_FLAG = "InAuthentication";
    public static final String IN_AUTHORIZATION_FLAG = "InAuthorization";
    public static final String SYSTEM_ACCOUNT_AUTHENTICATION = "SystemAccountAuthentication";

    private boolean listenerConfigured = false;

    private boolean authorizationInfoRequired = false;

    @Inject
    private AuthenticationInfoProviderHandler authenticationInfoProviderHandler;

    @Inject
    private OctopusWebConfiguration config;

    @Inject
    private CodecUtil codecUtil;

    @PostConstruct
    public void init() {
        // FIXME Is this not the default?
        setCachingEnabled(true);

    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        WebThreadContext.put(IN_AUTHORIZATION_FLAG, new InAuthorization());
        AuthorizationInfo authorizationInfo;
        try {
            Object primaryPrincipal = principals.getPrimaryPrincipal();

            if (OctopusWebSecurityContext.isSystemAccount(primaryPrincipal)) {
                // No permissions or roles, use @SystemAccount
                authorizationInfo = new SimpleAuthorizationInfo();  // TODO
            } else {
                //authorizationInfo = securityDataProvider.getAuthorizationInfo(principals);
            }
            //authorizationInfo = securityDataProvider.getAuthorizationInfo(principals);
            authorizationInfo = null; // FIXME ?? Why it is called twice, also in case of SystemAccount?
        } finally {

            WebThreadContext.remove(IN_AUTHORIZATION_FLAG);
        }
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo authenticationInfo = null;

        if (token instanceof SystemAccountAuthenticationToken) {
            // TODO Check about the realm names
            authenticationInfo = new SimpleAuthenticationInfo(token.getPrincipal(), ""); // FIXME custom constructor
        } else {
            if (!(token instanceof IncorrectDataToken)) {
                WebThreadContext.put(IN_AUTHENTICATION_FLAG, new InAuthentication());
                try {
                    authenticationInfo = authenticationInfoProviderHandler.retrieveAuthenticationInfo(token);
                    verifyHashEncoding(authenticationInfo);
                } finally {
                    // Even in the case of an exception (access not allowed) we need to reset this flag
                    WebThreadContext.remove(IN_AUTHENTICATION_FLAG);
                }
            }
        }
        return authenticationInfo;
    }

    private void verifyHashEncoding(AuthenticationInfo info) {
        if (!config.getHashAlgorithmName().isEmpty()) {
            Object credentials = info.getCredentials();

            if (credentials instanceof String || credentials instanceof char[]) {

                byte[] storedBytes = codecUtil.toBytes(credentials);
                HashEncoding hashEncoding = config.getHashEncoding();

                try {
                    // Lets try to decode, if we have an issue the supplied hash password is invalid.
                    switch (hashEncoding) {

                        case HEX:
                            Hex.decode(storedBytes);
                            break;
                        case BASE64:
                            Base64.decode(storedBytes);
                            break;
                        default:
                            throw new IllegalArgumentException("hashEncoding " + hashEncoding + " not supported");

                    }
                } catch (IllegalArgumentException e) {
                    throw new CredentialsException("Supplied hashed password can't be decoded. Is the 'hashEncoding' correctly set?");
                }
            }

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
        WebThreadContext.put(SYSTEM_ACCOUNT_AUTHENTICATION, new InSystemAccountAuthentication());
        try {
            super.assertCredentialsMatch(token, info);
        } finally {
            WebThreadContext.remove(SYSTEM_ACCOUNT_AUTHENTICATION);
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

    public static class InAuthentication {

        private InAuthentication() {
        }
    }

    public static class InAuthorization {

        private InAuthorization() {
        }
    }

    public static final class InSystemAccountAuthentication {
        // So that we only can create this class from this class.
        private InSystemAccountAuthentication() {
        }
    }

}
