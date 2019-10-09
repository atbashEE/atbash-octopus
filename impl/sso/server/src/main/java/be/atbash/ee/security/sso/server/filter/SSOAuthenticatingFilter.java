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
package be.atbash.ee.security.sso.server.filter;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.WebConstants;
import be.atbash.ee.security.octopus.authc.IncorrectDataToken;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.filter.authc.AuthenticatingFilter;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.ee.security.sso.server.endpoint.AccessTokenTransformer;
import be.atbash.ee.security.sso.server.store.OIDCStoreData;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.util.CDIUtils;
import com.nimbusds.oauth2.sdk.Scope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * TODO User endpoint must use https. Config parameter to disable this check (as sometime OIDC based server used purely internally.)
 * But when disabled, put a warning message in the log.
 */
@ApplicationScoped
public class SSOAuthenticatingFilter extends AuthenticatingFilter {

    private Logger logger = LoggerFactory.getLogger(SSOAuthenticatingFilter.class);

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private OctopusCoreConfiguration coreConfiguration;

    private AccessTokenTransformer accessTokenTransformer;

    @PostConstruct
    public void init() {
        setName("ssoFilter");
        accessTokenTransformer = CDIUtils.retrieveOptionalInstance(AccessTokenTransformer.class);
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {

        HttpServletRequest httpServletRequest = WebUtils.toHttp(request);
        String token = httpServletRequest.getHeader(OctopusConstants.AUTHORIZATION_HEADER);

        return createSSOToken(httpServletRequest, token);
    }

    private AuthenticationToken createSSOToken(ServletRequest request, String token) {

        if (token == null) {
            // Authorization header parameter is required.
            return new IncorrectDataToken("Authorization header required");
        }

        String[] parts = token.split(" ");
        if (parts.length != 2) {
            return new IncorrectDataToken("Authorization header value incorrect");
        }

        if (!OctopusConstants.BEARER.equals(parts[0])) {
            return new IncorrectDataToken("Authorization header value must start with Bearer");
        }

        OctopusSSOToken octopusToken = createOctopusToken(request, parts[1]);
        if (octopusToken == null) {
            return new IncorrectDataToken("Authentication failed");
        }
        return octopusToken;

    }

    private OctopusSSOToken createOctopusToken(ServletRequest request, String token) {
        String accessToken = null;

        String realToken;
        // Special custom requirements to the accessToken like signed tokens
        if (accessTokenTransformer != null) {
            realToken = accessTokenTransformer.transformAccessToken(token);
        } else {
            realToken = token;
        }

        UserPrincipal userPrincipal = tokenStore.getUserByAccessCode(realToken);

        OctopusSSOToken result = createSSOToken(userPrincipal);

        if (result != null) {
            // We have found a User for the token.
            accessToken = realToken;
        }

        if (result == null) {
            logger.info("No user information found for token " + token);
        } else {
            // Put the scope on the request so that the endpoint can use this information
            OIDCStoreData oidcStoreData = tokenStore.getOIDCDataByAccessToken(accessToken);
            request.setAttribute(Scope.class.getName(), oidcStoreData.getScope());

            showDebugInfo(result);
        }
        return result;
    }

    private OctopusSSOToken createSSOToken(UserPrincipal userPrincipal) {
        if (userPrincipal == null) {
            // No UserPrincipal known for the Bearer token
            return null;
        }
        OctopusSSOToken ssoUser = new OctopusSSOToken();

        String externalId = userPrincipal.getExternalId();
        if (externalId == null) {
            externalId = userPrincipal.getId().toString();
        }
        ssoUser.setId(externalId);

        Object localId = userPrincipal.getLocalId();
        if (localId == null) {
            localId = userPrincipal.getId();
        }
        ssoUser.setLocalId(localId.toString());

        ssoUser.setFullName(userPrincipal.getName());
        ssoUser.setFirstName(userPrincipal.getFirstName());
        ssoUser.setLastName(userPrincipal.getLastName());
        ssoUser.setEmail(userPrincipal.getEmail());
        ssoUser.setUserName(userPrincipal.getUserName());
        // FIXME Verify if authenticated from SSO Cookie
        ssoUser.setCookieToken(userPrincipal.getUserInfo(WebConstants.SSO_COOKIE_TOKEN));
        ssoUser.addUserInfo(userPrincipal.getInfo());
        return ssoUser;

    }

    private void showDebugInfo(OctopusSSOToken token) {
        /*
        if (coreConfiguration == null) {
            octopusConfig = BeanProvider.getContextualReference(OctopusConfig.class);
            logger = LoggerFactory.getLogger(SSOAuthenticatingFilter.class);
        }
         */

        if (coreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("(SSO Server) User %s is authenticated from Authorization Header (cookie token = %s)", token.getFullName(), token.getCookieToken()));
        }
    }


    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return executeLogin(request, response);
    }

    /*
    FIXME Review is this required to handle incorrect Bearer Token?
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {
        if (e != null) {
            throw e; // Propagate the error further so that UserRest filter can properly handle it.
        }
        return super.onLoginFailure(token, null, request, response);
    }


     * Overrides the default behavior to show and swallow the exception if the exception is
     * {@link org.apache.shiro.authz.UnauthenticatedException}.

    @Override
    protected void cleanup(ServletRequest request, ServletResponse response, Exception existing) throws ServletException, IOException {
        Exception exception = existing;
        Throwable unauthorized = OctopusUnauthorizedException.getUnauthorizedException(exception);
        if (unauthorized != null) {
            try {
                ((HttpServletResponse) response).setStatus(401);
                response.getOutputStream().println(unauthorized.getMessage());
                exception = null;
            } catch (Exception e) {
                exception = e;
            }
        }
        super.cleanup(request, response, exception);

    }

     */
}
