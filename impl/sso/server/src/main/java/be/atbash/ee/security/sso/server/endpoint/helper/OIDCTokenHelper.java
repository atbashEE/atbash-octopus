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
package be.atbash.ee.security.sso.server.endpoint.helper;

import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.openid.connect.sdk.AuthenticationRequest;
import be.atbash.ee.openid.connect.sdk.Nonce;
import be.atbash.ee.openid.connect.sdk.claims.IDTokenClaimsSet;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.util.TimeUtil;
import be.atbash.ee.security.octopus.util.URLUtil;
import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.client.ClientInfoRetriever;
import be.atbash.ee.security.sso.server.config.OctopusSSOServerConfiguration;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class OIDCTokenHelper {

    @Inject
    private OctopusSSOServerConfiguration ssoServerConfiguration;

    @Inject
    private URLUtil urlUtil;

    @Inject
    private TimeUtil timeUtil;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    public IDTokenClaimsSet defineIDToken(HttpServletRequest httpServletRequest, UserPrincipal userPrincipal, ClientID clientId) {
        return defineIDToken(httpServletRequest, userPrincipal, clientId, null);
    }

    public IDTokenClaimsSet defineIDToken(HttpServletRequest httpServletRequest, UserPrincipal userPrincipal, ClientID clientId, AuthenticationRequest request) {

        Issuer iss = new Issuer(urlUtil.determineRoot(httpServletRequest));
        Subject sub = new Subject(userPrincipal.getName());
        List<Audience> audList = new Audience(clientId.getValue()).toSingleAudienceList();

        Date iat = new Date();
        Date exp = timeUtil.addSecondsToDate(ssoServerConfiguration.getSSOAccessTokenTimeToLive(), iat); // TODO Verify how we handle expiration when multiple clients are using the server

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

        if (request != null) {
            Nonce nonce = request.getNonce();
            claimsSet.setNonce(nonce);
        }
        return claimsSet;
    }

    public SignedJWT signIdToken(ClientID clientId, IDTokenClaimsSet claimsSet) {
        SignedJWT idToken;
        try {

            ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(clientId.getValue());

            idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());

            idToken.sign(new MACSigner(clientInfo.getIdTokenSecret()));
        } catch (KeyLengthException e) {
            throw new ConfigurationException(e.getMessage());  // TODO Better informative message
            // Although, developers should take care that no invalid value can be stored (and thus retrieved here)
        } catch (OAuth2JSONParseException | JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }
        return idToken;
    }

}
