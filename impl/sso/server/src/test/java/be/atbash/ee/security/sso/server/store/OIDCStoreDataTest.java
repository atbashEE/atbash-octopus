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
package be.atbash.ee.security.sso.server.store;

import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.openid.connect.sdk.claims.IDTokenClaimsSet;
import be.atbash.ee.security.octopus.util.TimeUtil;
import be.atbash.util.BeanManagerFake;
import nl.jqno.equalsverifier.EqualsVerifier;
import nl.jqno.equalsverifier.Warning;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class OIDCStoreDataTest {

    private BeanManagerFake beanManagerFake;

    @BeforeEach
    public void setup() {
        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(new TimeUtil(), TimeUtil.class);

        beanManagerFake.endRegistration();
    }

    @Test
    public void testEqualsAndHashCode() {
        JsonObjectBuilder red = Json.createObjectBuilder();
        red.add("key", "value1");
        JsonObjectBuilder black = Json.createObjectBuilder();
        black.add("key", "value2");
        EqualsVerifier.forClass(OIDCStoreData.class)
                .withPrefabValues(JsonObject.class, red.build(), black.build())
                .suppress(Warning.NONFINAL_FIELDS)
                .withIgnoredFields("scope", "authorizationCode", "accessToken", "idTokenClaimsSet", "expiresOn")
                .verify();
    }

    @Test
    public void getterSetter() {
        List<Audience> audience = Audience.create("JUnit client");

        audience.add(new Audience("JUnit client"));

        IDTokenClaimsSet idTokenClaimSet = new IDTokenClaimsSet(new Issuer("tokenIssuer"), new Subject("JUnit"), audience, new Date(), new Date());
        BearerAccessToken accesToken = new BearerAccessToken(5, Scope.parse("openId"));
        OIDCStoreData oidcStoreData = new OIDCStoreData(accesToken);
        oidcStoreData.setIdTokenClaimsSet(idTokenClaimSet);

        IDTokenClaimsSet returnedData = oidcStoreData.getIdTokenClaimsSet();
        assertThat(returnedData.getIssuer().toJSONString()).isEqualTo("\"tokenIssuer\"");
        assertThat(returnedData.getSubject().toJSONString()).isEqualTo("\"JUnit\"");
        assertThat(returnedData.getAudience()).containsOnly(audience.toArray(new Audience[]{}));
        assertThat(returnedData.getExpirationTime()).isEqualTo(idTokenClaimSet.getExpirationTime());
        assertThat(returnedData.getIssueTime()).isEqualTo(idTokenClaimSet.getIssueTime());
    }

    @Test
    public void scopeFromAccessTokenSet() {

        BearerAccessToken accesToken = new BearerAccessToken(5, Scope.parse("openId Test"));
        OIDCStoreData oidcStoreData = new OIDCStoreData(accesToken);

        assertThat(oidcStoreData.getScope().contains("Test")).isTrue();

    }

    @Test
    public void getterSetter_noIdTokenClaimSet() {
        List<Audience> audience = Audience.create("JUnit client");

        audience.add(new Audience("JUnit client"));

        IDTokenClaimsSet idTokenClaimSet = new IDTokenClaimsSet(new Issuer("tokenIssuer"), new Subject("JUnit"), audience, new Date(), new Date());
        BearerAccessToken accesToken = new BearerAccessToken(5, Scope.parse("openId"));
        OIDCStoreData oidcStoreData = new OIDCStoreData(accesToken);

        IDTokenClaimsSet returnedData = oidcStoreData.getIdTokenClaimsSet();
        assertThat(returnedData).isNull();
    }

}