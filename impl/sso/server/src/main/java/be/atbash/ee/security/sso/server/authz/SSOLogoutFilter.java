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
package be.atbash.ee.security.sso.server.authz;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.filter.authz.AuthorizationFilter;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.ee.security.sso.server.token.UserPrincipalToken;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.LogoutRequest;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * Special filter for LogoutServlet.
 */
@ApplicationScoped
public class SSOLogoutFilter extends AuthorizationFilter {

    @Inject
    private SSOTokenStore tokenStore;

    @PostConstruct
    public void initInstance() {
        setName("ssoLogout");
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        WebSubject subject = getSubject();
        // If principal is not null, then the user is known and should be allowed access.
        boolean result = subject.getPrincipal() != null;
        if (!result) {
            result = checkFromRequest((HttpServletRequest) request);  // from Java SE logout
        }
        return result;

    }

    private boolean checkFromRequest(HttpServletRequest request) {
        boolean result = false;
        try {
            LogoutRequest logoutRequest = LogoutRequest.parse(request.getQueryString());
            // FIXME Validation of the JWT!!!!
            JWTClaimsSet claimsSet = logoutRequest.getIDTokenHint().getJWTClaimsSet();
            UserPrincipal userPrincipal = tokenStore.getUserByAccessCode(claimsSet.getSubject());

            try {
                SecurityUtils.getSubject().login(new UserPrincipalToken(userPrincipal));
                result = true;
            } catch (UnauthenticatedException e) {
                e.printStackTrace();
            }
        } catch (ParseException | java.text.ParseException e) {
            e.printStackTrace();
        }

        return result;
    }

}
