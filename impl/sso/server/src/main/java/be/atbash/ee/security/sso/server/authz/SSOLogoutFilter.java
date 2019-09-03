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
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.client.ClientInfoRetriever;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.ee.security.sso.server.token.UserPrincipalToken;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * Special filter for LogoutServlet.
 */
@ApplicationScoped
public class SSOLogoutFilter extends AuthorizationFilter {

    private Logger logger = LoggerFactory.getLogger(SSOLogoutFilter.class);

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @PostConstruct
    public void initInstance() {
        setName("ssoLogout");
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response) throws Exception {
        WebSubject subject = getSubject();
        // If principal is not null, then the user is known and should be allowed access.
        boolean alreadyAuthenticated = subject.getPrincipal() != null;

        boolean result = false;

        HttpServletRequest servletRequest = WebUtils.toHttp(request);
        try {
            LogoutRequest logoutRequest = LogoutRequest.parse(servletRequest.getQueryString());

            result = validate((SignedJWT) logoutRequest.getIDTokenHint());
            if (!result) {
                // Not valid, access is not allowed and we need to return true
                return result;
            }
            if (!alreadyAuthenticated) {
                // The Java SE case, in the web scenario we use the cookie to get user.
                JWTClaimsSet claimsSet = logoutRequest.getIDTokenHint().getJWTClaimsSet();
                UserPrincipal userPrincipal = tokenStore.getUserByAccessCode(claimsSet.getSubject());

                try {
                    SecurityUtils.getSubject().login(new UserPrincipalToken(userPrincipal));
                    result = true;
                } catch (UnauthenticatedException e) {
                    // .login() should never fail since UserPrincipalToken is SystemAuthenticationToken and ValidatedAuthenticationToken
                    throw new AtbashUnexpectedException(e);
                }
            }
        } catch (ParseException | java.text.ParseException e) {
            // TODO Add error codes
            logger.warn(String.format("SSOLogoutFilter: Parsing of the id_token_hint failed %s", request.getParameter("id_token_hint")));
        }

        return result;
    }

    private boolean validate(SignedJWT idTokenHint) {
        if (idTokenHint == null) {
            // TODO Add error codes
            logger.warn("SSOLogoutFilter: no query parameters found");
            return false;
        }

        try {
            String clientId = idTokenHint.getHeader().getCustomParam("clientId").toString();
            ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(clientId);
            if (clientInfo == null) {
                // TODO Add error codes
                logger.warn(String.format("SSOLogoutFilter: unknown clientId : %s", clientId));
                return false;
            }

            byte[] clientSecret = new Base64(clientInfo.getClientSecret()).decode();
            MACVerifier verifier = new MACVerifier(clientSecret);
            if (!idTokenHint.verify(verifier)) {
                // TODO Add error codes
                logger.warn(String.format("SSOLogoutFilter: JWT Signing verification failed : %s", idTokenHint.serialize()));
                return false;
            }

            boolean before = idTokenHint.getJWTClaimsSet().getExpirationTime().before(new Date());
            if (before) {
                // TODO Add error codes
                logger.warn(String.format("SSOLogoutFilter: JWT expired : %s", idTokenHint.serialize()));
            }
            return !before;
        } catch (JOSEException | java.text.ParseException e) {
            // No Exception to throw, MACVerifier failed or BASE64Decode failed
            return false;
        }
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
        WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return false;
    }
}
