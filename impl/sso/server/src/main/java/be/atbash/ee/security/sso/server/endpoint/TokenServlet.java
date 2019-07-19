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
package be.atbash.ee.security.sso.server.endpoint;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.client.ClientInfoRetriever;
import be.atbash.ee.security.sso.server.config.OctopusSSOServerConfiguration;
import be.atbash.ee.security.sso.server.store.OIDCStoreData;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@WebServlet("/octopus/sso/token")
public class TokenServlet extends HttpServlet {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenServlet.class);

    // These properties aren't related to any user info, so safe to use here.
    //@Inject
    //private SSOProducerBean ssoProducerBean;

    @Inject
    private OctopusSSOServerConfiguration ssoServerConfiguration;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private OIDCTokenHelper oidcTokenHelper;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @Inject
    private OctopusCoreConfiguration coreConfiguration;

    @Override
    protected void doPost(HttpServletRequest httpServletRequest, HttpServletResponse response) throws ServletException, IOException {

        TokenRequest tokenRequest = (TokenRequest) httpServletRequest.getAttribute(AbstractRequest.class.getName());

        TokenResponse tokenResponse = null;
        AuthorizationGrant grant = tokenRequest.getAuthorizationGrant();

        try {

            if (grant instanceof AuthorizationCodeGrant) {
                tokenResponse = getResponseAuthorizationGrant(response, tokenRequest, (AuthorizationCodeGrant) grant);
            }

            if (grant instanceof ResourceOwnerPasswordCredentialsGrant) {
                tokenResponse = getResponsePasswordGrant(httpServletRequest, response, tokenRequest, (ResourceOwnerPasswordCredentialsGrant) grant);
            }

            if (tokenResponse != null) {
                response.setContentType("application/json");

                if (!tokenResponse.indicatesSuccess()) {
                    // TODO Check if it is always an 400 when an TokenErrorResponse.
                    // OK for ResourceOwnerPasswordCredentialsGrant when invalid PW is supplied
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
                JSONObject jsonObject = tokenResponse.toHTTPResponse().getContentAsJSONObject();
                response.getWriter().append(jsonObject.toJSONString());
            }
        } catch (Exception e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new AtbashUnexpectedException(e);
        }
    }

    private TokenResponse getResponsePasswordGrant(HttpServletRequest httpServletRequest, HttpServletResponse response, TokenRequest tokenRequest, ResourceOwnerPasswordCredentialsGrant grant) {

        TokenResponse result;

        UsernamePasswordToken token = new UsernamePasswordToken(grant.getUsername(), grant.getPassword().getValue());

        try {
            SecurityUtils.getSubject().login(token);

            result = createTokensForPasswordGrant(httpServletRequest, tokenRequest);
        } catch (AuthenticationException e) {
            // OAuth2 (RFC 6749) 5.2.  Error Response
            ErrorObject errorObject = new ErrorObject("unauthorized_client", "ResourceOwnerPasswordCredentialsGrant is not allowed for client_id");
            return new TokenErrorResponse(errorObject);
        } catch (ParseException e) {
            throw new AtbashUnexpectedException(e);
        }

        // TODO, We should do a logout here I guess. Since we don't need anything from the session.
        //The tokenstore has the AccessCode which can be used to retrieve info about the user.
        return result;
    }

    private TokenResponse createTokensForPasswordGrant(HttpServletRequest httpServletRequest, TokenRequest tokenRequest) throws ParseException {

        IDTokenClaimsSet claimsSet = null;

        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(ssoServerConfiguration.getOIDCTokenLength()
                , ssoServerConfiguration.getSSOAccessTokenTimeToLive(), tokenRequest.getScope()));

        /*
        FIXME
        OctopusSSOUser ssoUser = ssoProducerBean.getOctopusSSOUser();

        if (tokenRequest.getScope() != null && tokenRequest.getScope().contains("openid")) {
            // TODO Study spec to see if these can be combined and it makes sense to do so?

            ClientID clientID = tokenRequest.getClientAuthentication().getClientID();
            // openid scope requires clientId
            claimsSet = oidcTokenHelper.defineIDToken(httpServletRequest, ssoUser, clientID);

            oidcStoreData.setClientId(clientID);
        }

        if (oidcStoreData.getClientId() != null) {
            ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(oidcStoreData.getClientId().getValue());
            if (!clientInfo.isDirectAccessAllowed()) {
                ErrorObject errorObject = new ErrorObject("unauthorized_client", "ResourceOwnerPasswordCredentialsGrant is not allowed for client_id");
                return new TokenErrorResponse(errorObject);
            }
        }
        oidcStoreData.setIdTokenClaimsSet(claimsSet);

        oidcStoreData.setScope(tokenRequest.getScope());

        String userAgent = httpServletRequest.getHeader("User-Agent");
        String remoteHost = httpServletRequest.getRemoteAddr();

        if (ssoUser.getCookieToken() == null) {
            tokenStore.addLoginFromClient(ssoUser, null, userAgent, remoteHost, oidcStoreData);
        } else {
            throw new AtbashIllegalActionException("Cannot allow password grant when SSO cookie is found");
        }
        */
        return defineResponse(oidcStoreData);
    }

    private AccessTokenResponse getResponseAuthorizationGrant(HttpServletResponse response, TokenRequest tokenRequest, AuthorizationCodeGrant codeGrant) throws ParseException {

        OIDCStoreData oidcStoreData = tokenStore.getOIDCDataByAuthorizationCode(codeGrant.getAuthorizationCode(), tokenRequest.getClientAuthentication().getClientID());
        if (oidcStoreData == null) {
            showErrorMessage(response, InvalidClientException.EXPIRED_SECRET);
            return null;
        }

        if (coreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            LOGGER.info(String.format("(SSO Server) Exchange Authorization code in an Access token ( %s -> %s )", codeGrant.getAuthorizationCode(), oidcStoreData.getAccessToken().getValue()));
        }

        return defineResponse(oidcStoreData);
    }

    private void showErrorMessage(HttpServletResponse response, InvalidClientException expiredSecret) {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        TokenErrorResponse tokenErrorResponse = new TokenErrorResponse(expiredSecret.getErrorObject());
        try {
            response.getWriter().println(tokenErrorResponse.toJSONObject().toJSONString());
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

    }

    private AccessTokenResponse defineResponse(OIDCStoreData oidcStoreData) throws ParseException {
        AccessTokenResponse result;

        if (oidcStoreData.getIdTokenClaimsSet() != null) {

            // RFC-6749 2. Must be signed ith JWS
            // TODO Support JWE?
            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
            // TODO We should also add the clientId to the token info, so that it can be used as id_token_hint for the logout request.
            SignedJWT signedJWT = new SignedJWT(header, oidcStoreData.getIdTokenClaimsSet().toJWTClaimsSet());

            // Apply the HMAC
            ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(oidcStoreData.getClientId().getValue());
            try {
                signedJWT.sign(new MACSigner(clientInfo.getIdTokenSecretByte()));
            } catch (JOSEException e) {
                throw new AtbashUnexpectedException(e);
            }

            OIDCTokens token = new OIDCTokens(signedJWT, oidcStoreData.getAccessToken(), null); // TODO refresh tokens
            result = new OIDCTokenResponse(token);
        } else {
            Tokens token = new Tokens(oidcStoreData.getAccessToken(), null); // TODO refresh tokens
            result = new AccessTokenResponse(token);
        }

        return result;

    }

    private void showDebugInfo(OctopusSSOToken user) {
        // TODO verify usage of String.format and + in logging.
        if (coreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            LOGGER.info(String.format("(SSO Server) User %s is authenticated and cookie written if needed.", user.getFullName()));
        }
    }
}
