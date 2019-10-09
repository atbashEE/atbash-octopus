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
package be.atbash.ee.security.octopus.sso.client.logout;

import be.atbash.ee.security.octopus.sso.client.JWSAlgorithmFactory;
import be.atbash.ee.security.octopus.sso.client.config.OctopusSSOServerClientConfiguration;
import be.atbash.ee.security.octopus.util.TimeUtil;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.net.URI;
import java.util.ArrayList;
import java.util.Date;

@ApplicationScoped
public class LogoutURLCreator {

    @Inject
    private OctopusSSOServerClientConfiguration ssoServerClientConfiguration;

    @Inject
    private JWSAlgorithmFactory jwsAlgorithmFactory;

    @Inject
    private TimeUtil timeUtil;

    private JWSAlgorithm algorithm;

    private Issuer issuer;

    @PostConstruct
    public void init() {
        algorithm = jwsAlgorithmFactory.determineOptimalAlgorithm(ssoServerClientConfiguration.getSSOClientSecret());
        issuer = new Issuer(ssoServerClientConfiguration.getSSOClientId());
    }

    public String createLogoutURL(String logoutURL, String accessToken) {

        Date iat = new Date();
        Date exp = timeUtil.addSecondsToDate(2, iat); // TODO Config parameter for time?

        Subject subject = new Subject(accessToken);  // AccessToken as the subject to identify the user.
        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(issuer, subject, new ArrayList<>(), exp, iat);

        SignedJWT idToken;
        try {
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(algorithm);
            headerBuilder.customParam("clientId", ssoServerClientConfiguration.getSSOClientId());

            idToken = new SignedJWT(headerBuilder.build(), claimsSet.toJWTClaimsSet());

            idToken.sign(new MACSigner(ssoServerClientConfiguration.getSSOClientSecret()));
        } catch (ParseException | JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }

        URI postLogoutRedirectURI = null;
        if (StringUtils.hasText(logoutURL)) {
            postLogoutRedirectURI = URI.create(logoutURL);
        }
        LogoutRequest result = new LogoutRequest(URI.create(ssoServerClientConfiguration.getLogoutPage()), idToken, postLogoutRedirectURI, null);
        return result.toURI().toASCIIString();
    }

    // for the Java SE case
    private static LogoutURLCreator INSTANCE;

    private static final Object LOCK = new Object();

    public static LogoutURLCreator getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new LogoutURLCreator();
                    INSTANCE.ssoServerClientConfiguration = OctopusSSOServerClientConfiguration.getInstance();
                    INSTANCE.jwsAlgorithmFactory = JWSAlgorithmFactory.getInstance();
                    INSTANCE.timeUtil = TimeUtil.getInstance();
                    INSTANCE.init();
                }
            }
        }
        return INSTANCE;
    }
}
