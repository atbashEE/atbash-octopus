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
package be.atbash.ee.security.octopus.oauth2.adapter;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.jadler.Jadler;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class ClientAuthenticationInfoProviderTest {

    private ClientAuthenticationInfoProvider provider;

    private String issuer;

    @Before
    public void setup() {
        Jadler.initJadler();
        provider = new ClientAuthenticationInfoProvider();
        defineDefaultConfigValues();
    }

    private void defineDefaultConfigValues() {

        TestConfig.addConfigValue("SSO.clientSecret", Base64.getEncoder().encodeToString("NotAGoodSecretButAnywayItIsOKForTesting".getBytes()));
        issuer = "http://localhost:" + Jadler.port() + "/root";
        TestConfig.addConfigValue("SSO.octopus.server", issuer);
        TestConfig.addConfigValue("SSO.clientId", "testClientId");
    }

    @After
    public void tearDown() {
        TestConfig.resetConfig();
        Jadler.closeJadler();
        System.setProperty("atbash.utils.cdi.check", "");
    }

    //@Test //FIXME On Commandline this gives error that Jadler is not listening ?
    public void getAuthenticationInfo() {
        Jadler.onRequest()
                .havingPathEqualTo("/root/octopus/sso/token")
                .respond()
                .withStatus(200)
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"token_type\":\"bearer\", \"access_token\":\"TheAccessCode\"}");

        long exp = DateUtils.toSecondsSinceEpoch(new Date()) + 5; //  5 is window for execution
        Jadler.onRequest()
                .havingPathEqualTo("/root/data/octopus/sso/user")
                .respond()
                .withStatus(200)
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody(String.format("{\"sub\":\"JUnit\", \"iss\":\"%s\", \"exp\":%s}", issuer, exp));

        AuthenticationToken token = new UsernamePasswordToken("user", "pw");

        AuthenticationInfo info = provider.getAuthenticationInfo(token);
        assertThat(info).isNotNull();  // It is enough to know we have something. The rest is already tested with other Unit tests.
    }

    @Test
    public void getAuthorizationInfo() {
        System.setProperty("atbash.utils.cdi.check", "false");

        UserPrincipal userPrincipal = new UserPrincipal(1L, "junit", "JUnit Test");

        OctopusSSOToken octopusSSOToken = new OctopusSSOToken();
        BearerAccessToken bearerAccessToken = new BearerAccessToken("theAccessToken");
        octopusSSOToken.setBearerAccessToken(bearerAccessToken);

        userPrincipal.addUserInfo(OctopusConstants.INFO_KEY_TOKEN, octopusSSOToken);
        PrincipalCollection collection = new PrincipalCollection(userPrincipal);

        TestConfig.addConfigValue("SSO.application", "test-app");

        Jadler.onRequest()
                .havingPathEqualTo("/root/data/octopus/sso/user/permissions/test-app")
                .havingHeaderEqualTo(OctopusConstants.AUTHORIZATION_HEADER, OctopusConstants.BEARER + " theAccessToken")
                .respond()
                .withStatus(200)
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"DEMO_WRITE\":\"demo:write:*\",\"DEMO_ACCESS\":\"demo:access:*\"}");

        AuthorizationInfo info = provider.getAuthorizationInfo(collection);
        assertThat(info).isNotNull();
        assertThat(info.getObjectPermissions()).hasSize(2);
        Set<String> names = new HashSet<>();
        Set<String> wildcards = new HashSet<>();
        for (Permission permission : info.getObjectPermissions()) {
            names.add(((NamedDomainPermission) permission).getName());
            wildcards.add(((NamedDomainPermission) permission).getWildcardNotation());
        }

        assertThat(names).containsOnly("DEMO_WRITE", "DEMO_ACCESS");
        assertThat(wildcards).containsOnly("demo:access:*", "demo:write:*");
    }

}