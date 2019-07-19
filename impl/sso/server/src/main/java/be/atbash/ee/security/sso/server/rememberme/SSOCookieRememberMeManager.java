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
package be.atbash.ee.security.sso.server.rememberme;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.rememberme.CookieRememberMeManager;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.SubjectContext;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.ee.security.sso.server.config.OctopusSSOServerConfiguration;
import be.atbash.ee.security.sso.server.cookie.SSOHelper;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.ee.security.sso.server.store.TokenStoreInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Specializes;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.util.UUID;

/**
 *
 */
@ApplicationScoped
@Specializes
public class SSOCookieRememberMeManager extends CookieRememberMeManager {

    private Logger logger = LoggerFactory.getLogger(SSOCookieRememberMeManager.class);

    @Inject
    private OctopusCoreConfiguration octopusConfig;

    @Inject
    private OctopusSSOServerConfiguration ssoServerConfiguration;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private SSOHelper ssoHelper;

    @PostConstruct
    public void init() {
        super.init();  // FIXME Required?

    }


    @Override
    public void onSuccessfulLogin(Subject subject, AuthenticationToken token, AuthenticationInfo info) {
        String clientId = ssoHelper.getSSOClientId(subject);
        if (clientId != null && !clientId.trim().isEmpty()) {
            rememberIdentity(subject, token, info);
        } else {
            super.onSuccessfulLogin(subject, token, info);
        }
    }

    @Override
    protected void rememberIdentity(Subject subject, PrincipalCollection accountPrincipals) {

        OctopusSSOToken ssoUser = accountPrincipals.oneByType(OctopusSSOToken.class);
        if (ssoUser != null) {

            // This cookieToken is only created the first time, not when authenticated from the cookie itself.
            String cookieToken = UUID.randomUUID().toString();
            ssoUser.setCookieToken(cookieToken);

            byte[] bytes = encrypt(cookieToken.getBytes());
            rememberSerializedIdentity(subject, bytes);
        }

    }

    public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
        PrincipalCollection principals = null;

        HttpServletRequest httpRequest = WebUtils.getHttpRequest(subjectContext);
        if (!WebUtils.getRequestUri(httpRequest).contains("/octopus/")) {
            // We are logging into the SSO server itself, not a client application.
            // Never use the SSO cookies for the main app itself.
            return null;
        }

        try {
            byte[] bytes = getRememberedSerializedIdentity(subjectContext);
            //SHIRO-138 - only call convertBytesToPrincipals if bytes exist:
            if (bytes != null && bytes.length > 0) {

                //String cookieToken = decrypt(bytes);
                // FIXME
                String cookieToken = "FIXME";

                UserPrincipal ssoUser = retrieveUserFromCookieToken(cookieToken, httpRequest);

                if (ssoUser != null) {
                    showDebugInfo(ssoUser);

                    // FIXME
                    //principals = new PrincipalCollection(ssoUser);
                }
            }
        } catch (RuntimeException re) {
            principals = onRememberedPrincipalFailure(re, subjectContext);
        }

        return principals;
    }

    public UserPrincipal retrieveUserFromCookieToken(String realToken, HttpServletRequest request) {
        // FIXME Verify the usage of UserPrincipal vc SSOUserToken
        UserPrincipal user = null;
        TokenStoreInfo cookieInfo = tokenStore.getUserByCookieToken(realToken);

        boolean result = verifyCookieInformation(cookieInfo, request);

        if (result) {
            user = cookieInfo.getUserPrincipal();
        }

        return user;
    }

    private boolean verifyCookieInformation(TokenStoreInfo cookieInfo, HttpServletRequest request) {
        boolean result = cookieInfo != null;
        if (result) {
            String remoteHost = request.getRemoteAddr();

            result = remoteHost.equals(cookieInfo.getRemoteHost());
        }
        if (result) {
            String userAgent = request.getHeader("User-Agent");

            result = userAgent.equals(cookieInfo.getUserAgent());
        }
        return result;
    }

    private void showDebugInfo(UserPrincipal user) {
        // FIXME
        /*
        if (octopusConfig == null) {
            octopusConfig = BeanProvider.getContextualReference(OctopusConfig.class);
        }

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("(SSO Server) User %s is authenticated from SSO Cookie %s (=cookie token)", user.getFullName(), user.getCookieToken()));
        }

         */
    }


}
