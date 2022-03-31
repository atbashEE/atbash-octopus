/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.sso.server.endpoint;

import be.atbash.ee.oauth2.sdk.AbstractRequest;
import be.atbash.ee.oauth2.sdk.AuthorizationCode;
import be.atbash.ee.oauth2.sdk.ResponseMode;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.jarm.JARMUtils;
import be.atbash.ee.oauth2.sdk.token.AccessToken;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.openid.connect.sdk.AuthenticationRequest;
import be.atbash.ee.openid.connect.sdk.AuthenticationSuccessResponse;
import be.atbash.ee.openid.connect.sdk.claims.IDTokenClaimsSet;
import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.WebConstants;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.sso.core.config.JARMLevel;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.util.PeriodUtil;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.ee.security.sso.server.config.OctopusSSOServerConfiguration;
import be.atbash.ee.security.sso.server.endpoint.helper.OIDCTokenHelper;
import be.atbash.ee.security.sso.server.store.OIDCStoreData;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

/**
 *
 */
@WebServlet("/octopus/sso/authenticate")
public class AuthenticationServlet extends HttpServlet {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationServlet.class);

    @Inject
    private OctopusSSOServerConfiguration ssoServerConfiguration;

    @Inject
    private JwtSupportConfiguration jwtSupportConfiguration;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private OctopusCoreConfiguration octopusCoreConfiguration;

    @Inject
    private OIDCTokenHelper oidcTokenHelper;

    @Inject
    private JWTEncoder jwtEncoder;

    private KeyManager keyManager;

    @Override
    public void init() throws ServletException {
        super.init();
        keyManager = jwtSupportConfiguration.getKeyManager();
    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse response) throws ServletException, IOException {

        UserPrincipal userPrincipal = SecurityUtils.getSubject().getPrincipal();
        // Get the info saved by the oidcFilter
        AuthenticationRequest request = (AuthenticationRequest) httpServletRequest.getAttribute(AbstractRequest.class.getName());

        ClientID clientId = request.getClientID();
        IDTokenClaimsSet claimsSet = oidcTokenHelper.defineIDToken(httpServletRequest, userPrincipal, clientId, request);

        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(ssoServerConfiguration.getOIDCTokenLength()
                , ssoServerConfiguration.getSSOAccessTokenTimeToLive(), request.getScope()));

        AuthorizationCode authorizationCode = null;
        AccessToken accessToken = null;

        SignedJWT idToken = null;

        if (request.getResponseType().impliesCodeFlow()) {
            authorizationCode = new AuthorizationCode(ssoServerConfiguration.getOIDCTokenLength());
            oidcStoreData.setAuthorizationCode(authorizationCode);

            // implicit -> idToken immediately transferred
            // code flow -> first code, then exchanged to accessToken/idToken
        } else {
            if (request.getResponseType().contains("token")) {
                // Set the variable so that the Access code is send in this response.
                accessToken = oidcStoreData.getAccessToken();
            }
            idToken = oidcTokenHelper.signIdToken(clientId, claimsSet);
        }

        State state = request.getState();

        AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(request.getRedirectionURI()
                , authorizationCode, idToken, accessToken, state, null, ResponseMode.QUERY);

        if (ssoServerConfiguration.getJARMLevel() != JARMLevel.NONE) {

            Issuer issuer = new Issuer(WebUtils.determineRoot(httpServletRequest));

            Date exp = new Date(new Date().getTime() + PeriodUtil.defineSecondsInPeriod(ssoServerConfiguration.getJarmJWTExpirationTime()));
            JWTClaimsSet jarmClaimSet = JARMUtils.toJWTClaimsSet(issuer, request.getClientID(), exp, successResponse);
            String jwt = jwtEncoder.encode(jarmClaimSet, getEncoderParameters());

            // redefine the AuthenticationSuccessResponse but now with the JWT/JWE
            try {
                successResponse = new AuthenticationSuccessResponse(request.getRedirectionURI()
                        , JWTParser.parse(jwt), ResponseMode.QUERY);
            } catch (ParseException e) {
                throw new AtbashUnexpectedException(e);
            }
        }

        oidcStoreData.setIdTokenClaimsSet(claimsSet);

        oidcStoreData.setClientId(request.getClientID());
        oidcStoreData.setScope(request.getScope());

        String userAgent = httpServletRequest.getHeader("User-Agent");
        String remoteHost = httpServletRequest.getRemoteAddr();

        String cookieToken = userPrincipal.getUserInfo(WebConstants.SSO_COOKIE_TOKEN);
        tokenStore.addLoginFromClient(SecurityUtils.getSubject().getPrincipal(), cookieToken, userAgent, remoteHost, oidcStoreData);


        try {
            String callback = successResponse.toURI().toString();

            showDebugInfo(userPrincipal);
            response.sendRedirect(callback);

            //SecurityUtils.getSubject().logout();// Do not use logout of subject, it wil remove the cookie which we need !
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new AtbashUnexpectedException(e);

        } finally {
            httpServletRequest.getSession().invalidate();  // Don't keep the session on the SSO server
        }


    }

    private JWTParameters getEncoderParameters() {
        JWTParameters result = null;
        switch (ssoServerConfiguration.getJARMLevel()) {

            case JWS:
                SelectorCriteria.Builder criteriaBuilder = SelectorCriteria.newBuilder();
                criteriaBuilder.withId(ssoServerConfiguration.getJarmSigningKeyId());
                List<AtbashKey> atbashKeys = keyManager.retrieveKeys(criteriaBuilder.build());

                if (atbashKeys.isEmpty()) {
                    throw new ConfigurationException(String.format("KeyManager does not know the key with id '%s'", ssoServerConfiguration.getJarmSigningKeyId()));
                }

                result = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS).withSecretKeyForSigning(atbashKeys.get(0))
                        .build();
                break;
            case JWE:
                break;
            default:
                throw new IllegalArgumentException(String.format("Value '%s' not supported for JARMLevel", ssoServerConfiguration.getJARMLevel()));
        }
        return result;
    }

    private void showDebugInfo(UserPrincipal userPrincipal) {
        if (octopusCoreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            LOGGER.info(String.format("(SSO Server) User %s is authenticated and cookie written if needed.", userPrincipal.getName()));
        }
    }


}
