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

import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.util.SecretUtil;
import be.atbash.ee.security.octopus.util.TimeUtil;
import be.atbash.ee.security.octopus.util.URLUtil;
import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.client.ClientInfoRetriever;
import be.atbash.ee.security.sso.server.config.OctopusSSOServerConfiguration;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class OIDCTokenHelperTest {

    @Mock
    private URLUtil urlUtilMock;

    @Mock
    private TimeUtil timeUtilMock;

    @Mock
    private OctopusSSOServerConfiguration ssoServerConfigurationMock;

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private ClientInfoRetriever clientInfoRetrieverMock;

    @Mock
    private AuthenticationRequest authenticationRequestMock;

    @InjectMocks
    private OIDCTokenHelper oidcTokenHelper;

    @Test
    public void defineIDToken() {

        when(urlUtilMock.determineRoot(httpServletRequestMock)).thenReturn("http://some.host/root");
        when(timeUtilMock.addSecondsToDate(anyLong(), any(Date.class))).thenReturn(new Date());
        when(ssoServerConfigurationMock.getSSOAccessTokenTimeToLive()).thenReturn(3600);
        when(authenticationRequestMock.getNonce()).thenReturn(new Nonce("nonceValue"));

        UserPrincipal userPrincipal = new UserPrincipal(1L, "junit", "JUnit test");

        ClientID clientId = new ClientID("JUnit_client");
        IDTokenClaimsSet claimsSet = oidcTokenHelper.defineIDToken(httpServletRequestMock, userPrincipal, clientId, authenticationRequestMock);

        assertThat(claimsSet.getAudience()).containsExactly(new Audience("JUnit_client"));
        assertThat(claimsSet.getIssuer()).isEqualTo(new Issuer("http://some.host/root"));
        assertThat(claimsSet.getSubject()).isEqualTo(new Subject("JUnit test"));
        assertThat(claimsSet.getExpirationTime()).isNotNull();
        assertThat(claimsSet.getIssueTime()).isNotNull();
        assertThat(claimsSet.getNonce()).isEqualTo(Nonce.parse("nonceValue"));

    }

    @Test
    public void signToken() throws JOSEException, ParseException, com.nimbusds.oauth2.sdk.ParseException {
        Issuer iss = new Issuer("http://some.host/root");
        Subject sub = new Subject("subject");
        List<Audience> audList = Audience.create("JUnit_client");
        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, new Date(), new Date());

        ClientInfo clientInfo = new ClientInfo();
        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String idTokenSecret = secretUtil.generateSecretBase64(48);
        clientInfo.setIdTokenSecret(idTokenSecret);

        when(clientInfoRetrieverMock.retrieveInfo("JUnit_client")).thenReturn(clientInfo);

        ClientID clientId = new ClientID("JUnit_client");
        SignedJWT signedJWT = oidcTokenHelper.signIdToken(clientId, claimsSet);

        signedJWT.verify(new MACVerifier(idTokenSecret));


        assertThat(signedJWT.getJWTClaimsSet().getClaims()).isEqualTo(claimsSet.toJWTClaimsSet().getClaims());

    }
}