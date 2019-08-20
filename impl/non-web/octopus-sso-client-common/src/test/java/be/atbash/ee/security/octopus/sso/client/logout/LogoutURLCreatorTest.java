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
import be.atbash.util.TestReflectionUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.SecureRandom;
import java.text.ParseException;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class LogoutURLCreatorTest {

    @Mock
    private OctopusSSOServerClientConfiguration ssoServerClientConfigurationMock;

    @Mock
    private JWSAlgorithmFactory jwsAlgorithmFactoryMock;

    @InjectMocks
    private LogoutURLCreator logoutURLCreator;

    @Test
    public void postProcessLogoutUrl() throws NoSuchFieldException, ParseException {
        TestReflectionUtils.setFieldValue(logoutURLCreator, "timeUtil", new TimeUtil());
        byte[] secret = defineSecret();
        when(ssoServerClientConfigurationMock.getSSOClientSecret()).thenReturn(secret);

        when(jwsAlgorithmFactoryMock.determineOptimalAlgorithm(any(byte[].class))).thenReturn(JWSAlgorithm.HS256);
        when(ssoServerClientConfigurationMock.getSSOClientId()).thenReturn("junit-clientId");
        String serverURL = "http://sso.server/root";
        when(ssoServerClientConfigurationMock.getLogoutPage()).thenReturn(serverURL);

        logoutURLCreator.init();
        String logoutUrl = logoutURLCreator.createLogoutURL("http://main.url/root/original/Logout", "theAccessToken");

        assertThat(logoutUrl).startsWith(serverURL);
        Map<String, List<String>> params = URLUtils.parseParameters(logoutUrl.substring(serverURL.length() + 1));
        assertThat(params).containsKeys("post_logout_redirect_uri", "id_token_hint");

        assertThat(params.get("post_logout_redirect_uri").get(0)).isEqualTo("http://main.url/root/original/Logout");
        SignedJWT jwt = SignedJWT.parse(params.get("id_token_hint").get(0));
        JWSHeader jwsHeader = jwt.getHeader();
        Set<Map.Entry<String, Object>> headerSet = jwsHeader.toJSONObject().entrySet();
        Map<String, Object> data = convertToMap(headerSet);
        assertThat(data).containsEntry("alg", "HS256");
        assertThat(data).containsEntry("clientId", "junit-clientId");

        Set<Map.Entry<String, Object>> claimSet = jwt.getJWTClaimsSet().toJSONObject().entrySet();
        data = convertToMap(claimSet);
        assertThat(data).containsEntry("iss", "junit-clientId");
        assertThat(data).containsEntry("sub", "theAccessToken");

        Date iat = DateUtils.fromSecondsSinceEpoch((Long) data.get("iat"));
        Date exp = DateUtils.fromSecondsSinceEpoch((Long) data.get("exp"));
        Date now = new Date();
        assertThat(now).isBetween(iat, exp);
        assertThat(exp.getTime() - iat.getTime()).isEqualTo(2000); // 2 seconds
    }

    private Map<String, Object> convertToMap(Set<Map.Entry<String, Object>> headerSet) {
        Map<String, Object> data = new HashMap<>();
        for (Map.Entry<String, Object> entry : headerSet) {
            data.put(entry.getKey(), entry.getValue());
        }
        return data;
    }

    private byte[] defineSecret() {
        byte[] secret = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(secret);
        return secret;
    }
}