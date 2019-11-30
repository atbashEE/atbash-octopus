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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.openid.connect.sdk.claims.ClaimRequirement;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.Test;

import javax.json.JsonObject;
import javax.json.JsonValue;
import java.net.URI;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the claims request class.
 */
public class ClaimsRequestTest {


    private static boolean containsVoluntaryClaimsRequestEntry(Collection<ClaimsRequest.Entry> entries,
                                                               String claimName) {

        for (ClaimsRequest.Entry en : entries) {

            if (en.getClaimName().equals(claimName) &&
                    en.getClaimRequirement().equals(ClaimRequirement.VOLUNTARY) &&
                    en.getValue() == null &&
                    en.getValues() == null) {
                return true;
            }
        }

        return false;
    }


    private static boolean containsEssentialClaimsRequestEntry(Collection<ClaimsRequest.Entry> entries,
                                                               String claimName) {

        for (ClaimsRequest.Entry en : entries) {

            if (en.getClaimName().equals(claimName) &&
                    en.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL) &&
                    en.getValue() == null &&
                    en.getValues() == null) {
                return true;
            }
        }

        return false;
    }

    @Test
    public void testResolveOAuthAuthorizationRequestWithNoScope() {

        ClaimsRequest cr = ClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null);
        assertThat(cr.getIDTokenClaims().isEmpty()).isTrue();
        assertThat(cr.getUserInfoClaims().isEmpty()).isTrue();

        cr = ClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null, (Map) null);
        assertThat(cr.getIDTokenClaims().isEmpty()).isTrue();
        assertThat(cr.getUserInfoClaims().isEmpty()).isTrue();

        cr = ClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null, (ClaimsRequest) null);
        assertThat(cr.getIDTokenClaims().isEmpty()).isTrue();
        assertThat(cr.getUserInfoClaims().isEmpty()).isTrue();

        cr = ClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null, null, null);
        assertThat(cr.getIDTokenClaims().isEmpty()).isTrue();
        assertThat(cr.getUserInfoClaims().isEmpty()).isTrue();
    }

    @Test
    public void testResolveSimple()
            throws Exception {

        Scope scope = Scope.parse("openid");

        ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("code"), scope);

        System.out.println("Claims request for scope openid: " + cr.toJSONObject());

        assertThat(cr.getIDTokenClaims().isEmpty()).isTrue();
        assertThat(cr.getUserInfoClaims().isEmpty()).isTrue();
    }

    @Test
    public void testResolveToUserInfo()
            throws Exception {

        Scope scope = Scope.parse("openid email profile phone address");

        ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("code"), scope);

        System.out.println("Claims request for scope openid email profile phone address: " + cr.toJSONObject());

        assertThat(cr.getIDTokenClaims().isEmpty()).isTrue();

        Collection<ClaimsRequest.Entry> userInfoClaims = cr.getUserInfoClaims();

        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified")).isTrue();

        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "given_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "family_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "middle_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "nickname")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "preferred_username")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "profile")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "picture")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "website")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "gender")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "birthdate")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "zoneinfo")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "locale")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "updated_at")).isTrue();

        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "phone_number")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "phone_number_verified")).isTrue();

        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "address")).isTrue();

        assertThat(userInfoClaims).hasSize(19);

        Set<String> claimNames = cr.getIDTokenClaimNames();
        assertThat(claimNames.isEmpty()).isTrue();

        claimNames = cr.getUserInfoClaimNames();

        assertThat(claimNames.contains("email")).isTrue();
        assertThat(claimNames.contains("email_verified")).isTrue();
        assertThat(claimNames.contains("name")).isTrue();
        assertThat(claimNames.contains("given_name")).isTrue();
        assertThat(claimNames.contains("family_name")).isTrue();
        assertThat(claimNames.contains("middle_name")).isTrue();
        assertThat(claimNames.contains("nickname")).isTrue();
        assertThat(claimNames.contains("preferred_username")).isTrue();
        assertThat(claimNames.contains("profile")).isTrue();
        assertThat(claimNames.contains("picture")).isTrue();
        assertThat(claimNames.contains("website")).isTrue();
        assertThat(claimNames.contains("gender")).isTrue();
        assertThat(claimNames.contains("birthdate")).isTrue();
        assertThat(claimNames.contains("zoneinfo")).isTrue();
        assertThat(claimNames.contains("locale")).isTrue();
        assertThat(claimNames.contains("updated_at")).isTrue();
        assertThat(claimNames.contains("phone_number")).isTrue();
        assertThat(claimNames.contains("phone_number_verified")).isTrue();
        assertThat(claimNames.contains("address")).isTrue();

        assertThat(claimNames).hasSize(19);
    }

    @Test
    public void testResolveToIDToken()
            throws Exception {

        Scope scope = Scope.parse("openid email profile phone address");

        ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("id_token"), scope);

        System.out.println("Claims request for scope openid email profile phone address: " + cr.toJSONObject());
        assertThat(cr.getUserInfoClaims().isEmpty()).isTrue();

        Collection<ClaimsRequest.Entry> idTokenClaims = cr.getIDTokenClaims();

        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "email")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "email_verified")).isTrue();

        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "given_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "family_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "middle_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "nickname")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "preferred_username")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "profile")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "picture")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "website")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "gender")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "birthdate")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "zoneinfo")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "locale")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "updated_at")).isTrue();

        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "phone_number")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "phone_number_verified")).isTrue();

        assertThat(containsVoluntaryClaimsRequestEntry(idTokenClaims, "address")).isTrue();

        assertThat(idTokenClaims).hasSize(19);

        Set<String> claimNames = cr.getUserInfoClaimNames();
        assertThat(claimNames.isEmpty()).isTrue();

        claimNames = cr.getIDTokenClaimNames();

        assertThat(claimNames.contains("email")).isTrue();
        assertThat(claimNames.contains("email_verified")).isTrue();
        assertThat(claimNames.contains("name")).isTrue();
        assertThat(claimNames.contains("given_name")).isTrue();
        assertThat(claimNames.contains("family_name")).isTrue();
        assertThat(claimNames.contains("middle_name")).isTrue();
        assertThat(claimNames.contains("nickname")).isTrue();
        assertThat(claimNames.contains("preferred_username")).isTrue();
        assertThat(claimNames.contains("profile")).isTrue();
        assertThat(claimNames.contains("picture")).isTrue();
        assertThat(claimNames.contains("website")).isTrue();
        assertThat(claimNames.contains("gender")).isTrue();
        assertThat(claimNames.contains("birthdate")).isTrue();
        assertThat(claimNames.contains("zoneinfo")).isTrue();
        assertThat(claimNames.contains("locale")).isTrue();
        assertThat(claimNames.contains("updated_at")).isTrue();
        assertThat(claimNames.contains("phone_number")).isTrue();
        assertThat(claimNames.contains("phone_number_verified")).isTrue();
        assertThat(claimNames.contains("address")).isTrue();

        assertThat(claimNames).hasSize(19);
    }

    @Test
    public void testResolveDependingOnResponseType()
            throws Exception {

        Scope scope = Scope.parse("openid email");

        ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("id_token code"), scope);

        assertThat(cr.getIDTokenClaims().isEmpty()).isTrue();

        Collection<ClaimsRequest.Entry> userInfoClaims = cr.getUserInfoClaims();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified")).isTrue();

        cr = ClaimsRequest.resolve(ResponseType.parse("id_token token"), scope);

        assertThat(cr.getIDTokenClaims().isEmpty()).isTrue();

        userInfoClaims = cr.getUserInfoClaims();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified")).isTrue();
    }

    @Test
    public void testAdd()
            throws Exception {

        Scope scope = Scope.parse("openid profile");

        ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("code"), scope);

        System.out.println("Claims request for scope openid profile: " + cr.toJSONObject());

        assertThat(cr.getIDTokenClaims().isEmpty()).isTrue();

        Collection<ClaimsRequest.Entry> userInfoClaims = cr.getUserInfoClaims();

        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "given_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "family_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "middle_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "nickname")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "preferred_username")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "profile")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "picture")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "website")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "gender")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "birthdate")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "zoneinfo")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "locale")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "updated_at")).isTrue();

        assertThat(userInfoClaims).hasSize(14);


        ClaimsRequest addon = new ClaimsRequest();
        addon.addUserInfoClaim("email", ClaimRequirement.ESSENTIAL);
        addon.addUserInfoClaim("email_verified", ClaimRequirement.ESSENTIAL);

        System.out.println("Essential claims request: " + addon.toJSONObject());

        cr.add(addon);


        assertThat(containsEssentialClaimsRequestEntry(userInfoClaims, "email")).isTrue();
        assertThat(containsEssentialClaimsRequestEntry(userInfoClaims, "email_verified")).isTrue();

        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "given_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "family_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "middle_name")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "nickname")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "preferred_username")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "profile")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "picture")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "website")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "gender")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "birthdate")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "zoneinfo")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "locale")).isTrue();
        assertThat(containsVoluntaryClaimsRequestEntry(userInfoClaims, "updated_at")).isTrue();

        assertThat(userInfoClaims).hasSize(16);


        Set<String> claimNames = cr.getIDTokenClaimNames();
        assertThat(claimNames.isEmpty()).isTrue();

        claimNames = cr.getUserInfoClaimNames();

        assertThat(claimNames.contains("email")).isTrue();
        assertThat(claimNames.contains("email_verified")).isTrue();
        assertThat(claimNames.contains("name")).isTrue();
        assertThat(claimNames.contains("given_name")).isTrue();
        assertThat(claimNames.contains("family_name")).isTrue();
        assertThat(claimNames.contains("middle_name")).isTrue();
        assertThat(claimNames.contains("nickname")).isTrue();
        assertThat(claimNames.contains("preferred_username")).isTrue();
        assertThat(claimNames.contains("profile")).isTrue();
        assertThat(claimNames.contains("picture")).isTrue();
        assertThat(claimNames.contains("website")).isTrue();
        assertThat(claimNames.contains("gender")).isTrue();
        assertThat(claimNames.contains("birthdate")).isTrue();
        assertThat(claimNames.contains("zoneinfo")).isTrue();
        assertThat(claimNames.contains("locale")).isTrue();
        assertThat(claimNames.contains("updated_at")).isTrue();

        assertThat(claimNames).hasSize(16);
    }

    @Test
    public void testResolveSimpleOIDCRequest()
            throws Exception {

        AuthenticationRequest authRequest = new AuthenticationRequest(
                new URI("https://c2id.com/login"),
                ResponseType.parse("code"),
                Scope.parse("openid email"),
                new ClientID("123"),
                new URI("https://client.com/cb"),
                new State(),
                new Nonce());

        ClaimsRequest claimsRequest = ClaimsRequest.resolve(authRequest);

        assertThat(claimsRequest.getIDTokenClaims().isEmpty()).isTrue();

        Set<String> userInfoClaims = claimsRequest.getUserInfoClaimNames();
        assertThat(userInfoClaims.contains("email")).isTrue();
        assertThat(userInfoClaims.contains("email_verified")).isTrue();
        assertThat(userInfoClaims).hasSize(2);

        Map<String, List<String>> authRequestParams = authRequest.toParameters();

        authRequest = AuthenticationRequest.parse(new URI("https://c2id.com/login"), authRequestParams);

        claimsRequest = ClaimsRequest.resolve(authRequest);

        assertThat(claimsRequest.getIDTokenClaims().isEmpty()).isTrue();

        userInfoClaims = claimsRequest.getUserInfoClaimNames();
        assertThat(userInfoClaims.contains("email")).isTrue();
        assertThat(userInfoClaims.contains("email_verified")).isTrue();
        assertThat(userInfoClaims).hasSize(2);
    }

    @Test
    public void testResolveSimpleIDTokenRequest()
            throws Exception {

        AuthenticationRequest authRequest = new AuthenticationRequest(
                new URI("https://c2id.com/login"),
                ResponseType.parse("id_token"),
                Scope.parse("openid email"),
                new ClientID("123"),
                new URI("https://client.com/cb"),
                new State(),
                new Nonce());

        ClaimsRequest claimsRequest = ClaimsRequest.resolve(authRequest);

        assertThat(claimsRequest.getUserInfoClaims().isEmpty()).isTrue();

        Set<String> idTokenClaims = claimsRequest.getIDTokenClaimNames();
        assertThat(idTokenClaims.contains("email")).isTrue();
        assertThat(idTokenClaims.contains("email_verified")).isTrue();
        assertThat(idTokenClaims).hasSize(2);

        Map<String, List<String>> authRequestParams = authRequest.toParameters();

        authRequest = AuthenticationRequest.parse(new URI("https://c2id.com/login"), authRequestParams);

        claimsRequest = ClaimsRequest.resolve(authRequest);

        assertThat(claimsRequest.getUserInfoClaims().isEmpty()).isTrue();

        idTokenClaims = claimsRequest.getIDTokenClaimNames();
        assertThat(idTokenClaims.contains("email")).isTrue();
        assertThat(idTokenClaims.contains("email_verified")).isTrue();
        assertThat(idTokenClaims).hasSize(2);
    }

    @Test
    public void testResolveComplexOIDCRequest()
            throws Exception {

        ClaimsRequest cr = new ClaimsRequest();
        cr.addIDTokenClaim(new ClaimsRequest.Entry("email", ClaimRequirement.ESSENTIAL));

        AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid", "email"),
                new ClientID("123"),
                new URI("https://client.com/cb")).claims(cr).build();

        ClaimsRequest claimsRequest = ClaimsRequest.resolve(authRequest);

        Set<String> idTokenClaims = claimsRequest.getIDTokenClaimNames();
        assertThat(idTokenClaims.contains("email")).isTrue();
        assertThat(idTokenClaims).hasSize(1);

        Collection<ClaimsRequest.Entry> idTokenEntries = claimsRequest.getIDTokenClaims();
        assertThat(idTokenEntries).hasSize(1);
        ClaimsRequest.Entry entry = idTokenEntries.iterator().next();
        assertThat(entry.getClaimName()).isEqualTo("email");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);

        Set<String> userInfoClaims = claimsRequest.getUserInfoClaimNames();
        assertThat(userInfoClaims.contains("email")).isTrue();
        assertThat(userInfoClaims.contains("email_verified")).isTrue();
        assertThat(userInfoClaims).hasSize(2);


        Map<String, List<String>> authRequestParams = authRequest.toParameters();

        authRequest = AuthenticationRequest.parse(new URI("https://c2id.com/login"), authRequestParams);

        claimsRequest = ClaimsRequest.resolve(authRequest);

        idTokenClaims = claimsRequest.getIDTokenClaimNames();
        assertThat(idTokenClaims.contains("email")).isTrue();
        assertThat(idTokenClaims).hasSize(1);

        idTokenEntries = claimsRequest.getIDTokenClaims();
        assertThat(idTokenEntries).hasSize(1);
        entry = idTokenEntries.iterator().next();
        assertThat(entry.getClaimName()).isEqualTo("email");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);

        userInfoClaims = claimsRequest.getUserInfoClaimNames();
        assertThat(userInfoClaims.contains("email")).isTrue();
        assertThat(userInfoClaims.contains("email_verified")).isTrue();
        assertThat(userInfoClaims).hasSize(2);
    }

    @Test
    public void testParseCoreSpecExample()
            throws Exception {

        String json = "{\n" +
                "   \"userinfo\":\n" +
                "    {\n" +
                "     \"given_name\": {\"essential\": true},\n" +
                "     \"nickname\": null,\n" +
                "     \"email\": {\"essential\": true},\n" +
                "     \"email_verified\": {\"essential\": true},\n" +
                "     \"picture\": null,\n" +
                "     \"http://example.info/claims/groups\": null\n" +
                "    },\n" +
                "   \"id_token\":\n" +
                "    {\n" +
                "     \"auth_time\": {\"essential\": true},\n" +
                "     \"acr\": {\"values\": [\"urn:mace:incommon:iap:silver\"] }\n" +
                "    }\n" +
                "  }";

        JsonObject jsonObject = JSONObjectUtils.parse(json);

        ClaimsRequest claimsRequest = ClaimsRequest.parse(jsonObject);

        Set<String> idTokenClaimNames = claimsRequest.getIDTokenClaimNames();
        assertThat(idTokenClaimNames.contains("auth_time")).isTrue();
        assertThat(idTokenClaimNames.contains("acr")).isTrue();
        assertThat(idTokenClaimNames).hasSize(2);

        ClaimsRequest.Entry entry = claimsRequest.removeIDTokenClaim("auth_time");
        assertThat(entry.getClaimName()).isEqualTo("auth_time");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);

        entry = claimsRequest.removeIDTokenClaim("acr");
        assertThat(entry.getClaimName()).isEqualTo("acr");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues().contains("urn:mace:incommon:iap:silver")).isTrue();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);

        assertThat(claimsRequest.getIDTokenClaims().isEmpty()).isTrue();


        Set<String> userInfoClaimNames = claimsRequest.getUserInfoClaimNames();
        assertThat(userInfoClaimNames.contains("given_name")).isTrue();
        assertThat(userInfoClaimNames.contains("nickname")).isTrue();
        assertThat(userInfoClaimNames.contains("email")).isTrue();
        assertThat(userInfoClaimNames.contains("email_verified")).isTrue();
        assertThat(userInfoClaimNames.contains("picture")).isTrue();
        assertThat(userInfoClaimNames.contains("http://example.info/claims/groups")).isTrue();
        assertThat(userInfoClaimNames).hasSize(6);

        entry = claimsRequest.removeUserInfoClaim("given_name");
        assertThat(entry.getClaimName()).isEqualTo("given_name");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);

        entry = claimsRequest.removeUserInfoClaim("nickname");
        assertThat(entry.getClaimName()).isEqualTo("nickname");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);

        entry = claimsRequest.removeUserInfoClaim("email");
        assertThat(entry.getClaimName()).isEqualTo("email");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);

        entry = claimsRequest.removeUserInfoClaim("email_verified");
        assertThat(entry.getClaimName()).isEqualTo("email_verified");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);

        entry = claimsRequest.removeUserInfoClaim("picture");
        assertThat(entry.getClaimName()).isEqualTo("picture");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);

        entry = claimsRequest.removeUserInfoClaim("http://example.info/claims/groups");
        assertThat(entry.getClaimName()).isEqualTo("http://example.info/claims/groups");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);

        assertThat(claimsRequest.getUserInfoClaims().isEmpty()).isTrue();
    }

    @Test
    public void testParseIndividualClaimRequestWithAdditionalInformationExample()
            throws Exception {

        String json = "{\n" +
                "   \"userinfo\":\n" +
                "    {\n" +
                "     \"given_name\": {\"essential\": true},\n" +
                "     \"nickname\": null,\n" +
                "     \"email\": {\"essential\": true},\n" +
                "     \"email_verified\": {\"essential\": true},\n" +
                "     \"picture\": null,\n" +
                "     \"http://example.info/claims/groups\": null,\n" +
                "     \"http://example.info/claims/additionalInfo\": {\"info\" : \"custom information\"}\n" +
                "    },\n" +
                "   \"id_token\":\n" +
                "    {\n" +
                "     \"auth_time\": {\"essential\": true},\n" +
                "     \"acr\": {\"values\": [\"urn:mace:incommon:iap:silver\"] }\n" +
                "    }\n" +
                "  }";

        JsonObject jsonObject = JSONObjectUtils.parse(json);

        ClaimsRequest claimsRequest = ClaimsRequest.parse(jsonObject);

        Set<String> idTokenClaimNames = claimsRequest.getIDTokenClaimNames();
        assertThat(idTokenClaimNames.contains("auth_time")).isTrue();
        assertThat(idTokenClaimNames.contains("acr")).isTrue();
        assertThat(idTokenClaimNames).hasSize(2);

        ClaimsRequest.Entry entry = claimsRequest.removeIDTokenClaim("auth_time");
        assertThat(entry.getClaimName()).isEqualTo("auth_time");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);

        entry = claimsRequest.removeIDTokenClaim("acr");
        assertThat(entry.getClaimName()).isEqualTo("acr");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues().contains("urn:mace:incommon:iap:silver")).isTrue();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);

        assertThat(claimsRequest.getIDTokenClaims().isEmpty()).isTrue();


        Set<String> userInfoClaimNames = claimsRequest.getUserInfoClaimNames();
        assertThat(userInfoClaimNames.contains("given_name")).isTrue();
        assertThat(userInfoClaimNames.contains("nickname")).isTrue();
        assertThat(userInfoClaimNames.contains("email")).isTrue();
        assertThat(userInfoClaimNames.contains("email_verified")).isTrue();
        assertThat(userInfoClaimNames.contains("picture")).isTrue();
        assertThat(userInfoClaimNames.contains("http://example.info/claims/groups")).isTrue();
        assertThat(userInfoClaimNames.contains("http://example.info/claims/additionalInfo")).isTrue();
        assertThat(userInfoClaimNames).hasSize(7);

        entry = claimsRequest.removeUserInfoClaim("given_name");
        assertThat(entry.getClaimName()).isEqualTo("given_name");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);

        entry = claimsRequest.removeUserInfoClaim("nickname");
        assertThat(entry.getClaimName()).isEqualTo("nickname");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);

        entry = claimsRequest.removeUserInfoClaim("email");
        assertThat(entry.getClaimName()).isEqualTo("email");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);

        entry = claimsRequest.removeUserInfoClaim("email_verified");
        assertThat(entry.getClaimName()).isEqualTo("email_verified");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);

        entry = claimsRequest.removeUserInfoClaim("picture");
        assertThat(entry.getClaimName()).isEqualTo("picture");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);

        entry = claimsRequest.removeUserInfoClaim("http://example.info/claims/groups");
        assertThat(entry.getClaimName()).isEqualTo("http://example.info/claims/groups");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);

        entry = claimsRequest.removeUserInfoClaim("http://example.info/claims/additionalInfo");
        assertThat(entry.getClaimName()).isEqualTo("http://example.info/claims/additionalInfo");
        assertThat(entry.getValue()).isNull();
        assertThat(entry.getValues()).isNull();
        Map<String, Object> additionalInformation = entry.getAdditionalInformation();
        assertThat(additionalInformation).isNotNull();
        assertThat(additionalInformation.containsKey("info")).isTrue();
        assertThat(additionalInformation.get("info")).isEqualTo("custom information");
        assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);

        assertThat(claimsRequest.getUserInfoClaims().isEmpty()).isTrue();
    }

    @Test
    public void testAddAndRemoveIDTokenClaims()
            throws Exception {

        ClaimsRequest r = new ClaimsRequest();

        r.addIDTokenClaim("email");
        r.addIDTokenClaim("name");
        Map<String, Object> additionalInformationClaimA1 = new HashMap<>();
        additionalInformationClaimA1.put("info", "custom information");
        r.addIDTokenClaim("a-1", ClaimRequirement.ESSENTIAL, "a1", additionalInformationClaimA1);


        assertThat(r.getIDTokenClaimNames().contains("email")).isTrue();
        assertThat(r.getIDTokenClaimNames().contains("name")).isTrue();
        assertThat(r.getIDTokenClaimNames().contains("a-1")).isTrue();
        assertThat(r.getIDTokenClaims()).hasSize(3);

        JsonObject object = r.toJSONObject();
        assertThat(object).hasSize(1);

        JsonObject idTokenObject = object.getJsonObject("id_token");
        assertThat(idTokenObject.containsKey("email")).isTrue();
        assertThat(idTokenObject.get("email").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(idTokenObject.containsKey("name")).isTrue();
        assertThat(idTokenObject.get("name").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(idTokenObject.containsKey("a-1")).isTrue();
        assertThat(idTokenObject.get("a-1")).isNotNull();
        assertThat(idTokenObject).hasSize(3);

        r.removeIDTokenClaims("email");
        r.removeIDTokenClaims("name");
        r.removeIDTokenClaims("a-1");

        assertThat(r.getIDTokenClaimNames().contains("email")).isFalse();
        assertThat(r.getIDTokenClaimNames().contains("name")).isFalse();
        assertThat(r.getIDTokenClaimNames().contains("a-1")).isFalse();
        assertThat(r.getIDTokenClaims()).hasSize(0);

        object = r.toJSONObject();
        assertThat(object.isEmpty()).isTrue();
    }

    @Test
    public void testAddAndRemoveUserInfoClaims()
            throws Exception {

        ClaimsRequest r = new ClaimsRequest();

        r.addUserInfoClaim("email");
        r.addUserInfoClaim("name");
        Map<String, Object> additionalInformationClaimA1 = new HashMap<>();
        additionalInformationClaimA1.put("info", "custom information");
        r.addUserInfoClaim("a-1", ClaimRequirement.ESSENTIAL, "a1", additionalInformationClaimA1);

        assertThat(r.getUserInfoClaimNames().contains("email")).isTrue();
        assertThat(r.getUserInfoClaimNames().contains("name")).isTrue();
        assertThat(r.getUserInfoClaimNames().contains("a-1")).isTrue();
        assertThat(r.getUserInfoClaims()).hasSize(3);

        JsonObject object = r.toJSONObject();
        assertThat(object).hasSize(1);

        JsonObject userInfoObject = object.getJsonObject("userinfo");
        assertThat(userInfoObject.containsKey("email")).isTrue();
        assertThat(userInfoObject.get("email").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(userInfoObject.containsKey("name")).isTrue();
        assertThat(userInfoObject.get("name").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(userInfoObject.containsKey("a-1")).isTrue();
        assertThat(userInfoObject.get("a-1")).isNotNull();
        assertThat(userInfoObject).hasSize(3);

        r.removeUserInfoClaims("email");
        r.removeUserInfoClaims("name");
        r.removeUserInfoClaims("a-1");

        assertThat(r.getUserInfoClaimNames().contains("email")).isFalse();
        assertThat(r.getUserInfoClaimNames().contains("name")).isFalse();
        assertThat(r.getUserInfoClaimNames().contains("a-1")).isFalse();
        assertThat(r.getUserInfoClaims()).hasSize(0);

        object = r.toJSONObject();
        assertThat(object.isEmpty()).isTrue();
    }

    @Test
    public void testParseFromString()
            throws Exception {

        // Example from http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
        String json = "{\n" +
                "   \"userinfo\":\n" +
                "    {\n" +
                "     \"given_name\": {\"essential\": true},\n" +
                "     \"nickname\": null,\n" +
                "     \"email\": {\"essential\": true},\n" +
                "     \"email_verified\": {\"essential\": true},\n" +
                "     \"picture\": null,\n" +
                "     \"http://example.info/claims/groups\": null\n" +
                "    },\n" +
                "   \"id_token\":\n" +
                "    {\n" +
                "     \"auth_time\": {\"essential\": true},\n" +
                "     \"acr\": {\"values\": [\"urn:mace:incommon:iap:silver\"] }\n" +
                "    }\n" +
                "  }";

        ClaimsRequest claimsRequest = ClaimsRequest.parse(json);

        assertThat(claimsRequest.getUserInfoClaimNames().contains("given_name")).isTrue();
        assertThat(claimsRequest.getUserInfoClaimNames().contains("nickname")).isTrue();
        assertThat(claimsRequest.getUserInfoClaimNames().contains("email")).isTrue();
        assertThat(claimsRequest.getUserInfoClaimNames().contains("email_verified")).isTrue();
        assertThat(claimsRequest.getUserInfoClaimNames().contains("picture")).isTrue();
        assertThat(claimsRequest.getUserInfoClaimNames().contains("http://example.info/claims/groups")).isTrue();
        assertThat(claimsRequest.getUserInfoClaimNames()).hasSize(6);

        assertThat(claimsRequest.getIDTokenClaimNames().contains("auth_time")).isTrue();
        assertThat(claimsRequest.getIDTokenClaimNames().contains("acr")).isTrue();
        assertThat(claimsRequest.getIDTokenClaimNames()).hasSize(2);

        for (ClaimsRequest.Entry entry : claimsRequest.getUserInfoClaims()) {

            if (entry.getClaimName().equals("given_name")) {

                assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);
                assertThat(entry.getValue()).isNull();
                assertThat(entry.getValues()).isNull();

            } else if (entry.getClaimName().equals("nickname")) {

                assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);
                assertThat(entry.getValue()).isNull();
                assertThat(entry.getValues()).isNull();

            } else if (entry.getClaimName().equals("email")) {

                assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);
                assertThat(entry.getValue()).isNull();
                assertThat(entry.getValues()).isNull();

            } else if (entry.getClaimName().equals("email_verified")) {

                assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);
                assertThat(entry.getValue()).isNull();
                assertThat(entry.getValues()).isNull();

            } else if (entry.getClaimName().equals("picture")) {

                assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);
                assertThat(entry.getValue()).isNull();
                assertThat(entry.getValues()).isNull();

            } else if (entry.getClaimName().equals("http://example.info/claims/groups")) {

                assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);
                assertThat(entry.getValue()).isNull();
                assertThat(entry.getValues()).isNull();

            } else {
                fail("Unexpected userinfo claim name: " + entry.getClaimName());
            }
        }

        for (ClaimsRequest.Entry entry : claimsRequest.getIDTokenClaims()) {

            if (entry.getClaimName().equals("auth_time")) {

                assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.ESSENTIAL);
                assertThat(entry.getValue()).isNull();
                assertThat(entry.getValues()).isNull();

            } else if (entry.getClaimName().equals("acr")) {

                assertThat(entry.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);
                assertThat(entry.getValue()).isNull();
                assertThat(entry.getValues().contains("urn:mace:incommon:iap:silver")).isTrue();
                assertThat(entry.getValues()).hasSize(1);

            } else {
                fail("Unexpected id_token claim name: " + entry.getClaimName());
            }
        }
    }

    @Test
    public void testResolveCustomClaims_UserInfo() {

        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);

        Scope scope = new Scope("openid", "email", "custom-scope-a", "custom-scope-b");

        Map<Scope.Value, Set<String>> customClaims = new HashMap<>();
        customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
        customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
        customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));

        ClaimsRequest claimsRequest = ClaimsRequest.resolve(responseType, scope, customClaims);

        for (ClaimsRequest.Entry en : claimsRequest.getUserInfoClaims()) {
            assertThat(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName())).isTrue();
            assertThat(en.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);
        }

        assertThat(claimsRequest.getIDTokenClaims().isEmpty()).isTrue();
    }

    @Test
    public void testResolveCustomClaims_IDToken() {

        ResponseType responseType = new ResponseType(OIDCResponseTypeValue.ID_TOKEN);

        Scope scope = new Scope("openid", "email", "custom-scope-a", "custom-scope-b");

        Map<Scope.Value, Set<String>> customClaims = new HashMap<>();
        customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
        customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
        customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));

        ClaimsRequest claimsRequest = ClaimsRequest.resolve(responseType, scope, customClaims);

        assertThat(claimsRequest.getUserInfoClaims().isEmpty()).isTrue();

        for (ClaimsRequest.Entry en : claimsRequest.getIDTokenClaims()) {
            assertThat(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName())).isTrue();
            assertThat(en.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);
        }
    }

    @Test
    public void testResolveCustomClaims_UserInfo_withNullClaimsRequest() {

        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);

        Scope scope = new Scope("openid", "email", "custom-scope-a", "custom-scope-b");

        Map<Scope.Value, Set<String>> customClaims = new HashMap<>();
        customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
        customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
        customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));

        ClaimsRequest claimsRequest = ClaimsRequest.resolve(responseType, scope, null, customClaims);

        for (ClaimsRequest.Entry en : claimsRequest.getUserInfoClaims()) {
            assertThat(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName())).isTrue();
            assertThat(en.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);
        }

        assertThat(claimsRequest.getIDTokenClaims().isEmpty()).isTrue();
    }

    @Test
    public void testResolveCustomClaims_IDToken_withNullClaimsRequest() {

        ResponseType responseType = new ResponseType(OIDCResponseTypeValue.ID_TOKEN);

        Scope scope = new Scope("openid", "email", "custom-scope-a", "custom-scope-b");

        Map<Scope.Value, Set<String>> customClaims = new HashMap<>();
        customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
        customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
        customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));

        ClaimsRequest claimsRequest = ClaimsRequest.resolve(responseType, scope, null, customClaims);

        assertThat(claimsRequest.getUserInfoClaims().isEmpty()).isTrue();

        for (ClaimsRequest.Entry en : claimsRequest.getIDTokenClaims()) {
            assertThat(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName())).isTrue();
            assertThat(en.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);
        }
    }

    @Test
    public void testResolveCustomClaims_UserInfo_withClaimsRequest() {

        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);

        Scope scope = new Scope("openid", "custom-scope-a", "custom-scope-b");

        Map<Scope.Value, Set<String>> customClaims = new HashMap<>();
        customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
        customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
        customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));

        ClaimsRequest claimsRequest = new ClaimsRequest();
        claimsRequest.addUserInfoClaim("email");
        claimsRequest.addUserInfoClaim("email_verified");

        ClaimsRequest resolvedClaimsRequest = ClaimsRequest.resolve(responseType, scope, claimsRequest, customClaims);

        for (ClaimsRequest.Entry en : resolvedClaimsRequest.getUserInfoClaims()) {
            assertThat(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName())).isTrue();
            assertThat(en.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);
        }

        assertThat(resolvedClaimsRequest.getIDTokenClaims().isEmpty()).isTrue();
    }

    @Test
    public void testResolveCustomClaims_IDToken_withClaimsRequest() {

        ResponseType responseType = new ResponseType(OIDCResponseTypeValue.ID_TOKEN);

        Scope scope = new Scope("openid", "custom-scope-a", "custom-scope-b");

        Map<Scope.Value, Set<String>> customClaims = new HashMap<>();
        customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
        customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
        customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));

        ClaimsRequest claimsRequest = new ClaimsRequest();
        claimsRequest.addIDTokenClaim("email");
        claimsRequest.addIDTokenClaim("email_verified");

        ClaimsRequest resolvedClaimsRequest = ClaimsRequest.resolve(responseType, scope, claimsRequest, customClaims);

        assertThat(resolvedClaimsRequest.getUserInfoClaims().isEmpty()).isTrue();

        for (ClaimsRequest.Entry en : resolvedClaimsRequest.getIDTokenClaims()) {
            assertThat(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName())).isTrue();
            assertThat(en.getClaimRequirement()).isEqualTo(ClaimRequirement.VOLUNTARY);
        }
    }
}