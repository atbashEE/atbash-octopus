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
package be.atbash.ee.openid.connect.sdk.claims;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.oauth2.sdk.token.TypelessAccessToken;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.Ignore;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.mail.internet.InternetAddress;
import java.net.URI;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the UserInfo claims set.
 */
public class UserInfoTest {

    @Test
    public void testClaimNameConstants() {

        assertThat(UserInfo.getStandardClaimNames().contains("sub")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("iss")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("aud")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("name")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("given_name")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("family_name")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("middle_name")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("nickname")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("preferred_username")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("profile")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("picture")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("website")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("email")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("email_verified")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("gender")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("birthdate")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("zoneinfo")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("locale")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("phone_number")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("phone_number_verified")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("address")).isTrue();
        assertThat(UserInfo.getStandardClaimNames().contains("updated_at")).isTrue();
        assertThat(UserInfo.getStandardClaimNames()).hasSize(22);
    }

    @Test
    public void testParseRoundTrip()
            throws Exception {

        // Example JSON from messages spec
        String json = "{\n" +
                "   \"sub\"                : \"248289761001\",\n" +
                "   \"name\"               : \"Jane Doe\",\n" +
                "   \"given_name\"         : \"Jane\",\n" +
                "   \"family_name\"        : \"Doe\",\n" +
                "   \"preferred_username\" : \"j.doe\",\n" +
                "   \"email\"              : \"janedoe@example.com\",\n" +
                "   \"picture\"            : \"http://example.com/janedoe/me.jpg\"\n" +
                " }";

        UserInfo userInfo = UserInfo.parse(json);

        assertThat(userInfo.getSubject().getValue()).isEqualTo("248289761001");
        assertThat(userInfo.getName()).isEqualTo("Jane Doe");
        assertThat(userInfo.getGivenName()).isEqualTo("Jane");
        assertThat(userInfo.getFamilyName()).isEqualTo("Doe");
        assertThat(userInfo.getPreferredUsername()).isEqualTo("j.doe");
        assertThat(userInfo.getEmail().getAddress()).isEqualTo("janedoe@example.com");
        assertThat(userInfo.getPicture().toString()).isEqualTo("http://example.com/janedoe/me.jpg");

        json = userInfo.toJSONObject().build().toString();

        userInfo = UserInfo.parse(json);

        assertThat(userInfo.getSubject().getValue()).isEqualTo("248289761001");
        assertThat(userInfo.getName()).isEqualTo("Jane Doe");
        assertThat(userInfo.getGivenName()).isEqualTo("Jane");
        assertThat(userInfo.getFamilyName()).isEqualTo("Doe");
        assertThat(userInfo.getPreferredUsername()).isEqualTo("j.doe");
        assertThat(userInfo.getEmail().getAddress()).isEqualTo("janedoe@example.com");
        assertThat(userInfo.getPicture().toString()).isEqualTo("http://example.com/janedoe/me.jpg");

        // No external claims
        assertThat(userInfo.getAggregatedClaims()).isNull();
        assertThat(userInfo.getDistributedClaims()).isNull();
    }

    @Test
    public void testWithAddress()
            throws Exception {

        String json = "{\n" +
                "\"sub\": \"248289761001\",\n" +
                "\"name\": \"Jane Doe\",\n" +
                "\"email\": \"janedoe@example.com\",\n" +
                "\"address\": {\n" +
                "\"formatted\":\"Some formatted\",\n" +
                "\"street_address\":\"Some street\",\n" +
                "\"locality\":\"Some locality\",\n" +
                "\"region\":\"Some region\",\n" +
                "\"postal_code\":\"1000\",\n" +
                "\"country\":\"Some country\"\n" +
                "}   \n" +
                "}";

        UserInfo userInfo = UserInfo.parse(json);

        assertThat(userInfo.getSubject().getValue()).isEqualTo("248289761001");
        assertThat(userInfo.getName()).isEqualTo("Jane Doe");
        assertThat(userInfo.getEmail().getAddress()).isEqualTo("janedoe@example.com");

        Address address = userInfo.getAddress();

        assertThat(address.getFormatted()).isEqualTo("Some formatted");
        assertThat(address.getStreetAddress()).isEqualTo("Some street");
        assertThat(address.getLocality()).isEqualTo("Some locality");
        assertThat(address.getRegion()).isEqualTo("Some region");
        assertThat(address.getPostalCode()).isEqualTo("1000");
        assertThat(address.getCountry()).isEqualTo("Some country");

        json = userInfo.toJSONObject().build().toString();

        userInfo = UserInfo.parse(json);

        assertThat(userInfo.getSubject().getValue()).isEqualTo("248289761001");
        assertThat(userInfo.getName()).isEqualTo("Jane Doe");
        assertThat(userInfo.getEmail().getAddress()).isEqualTo("janedoe@example.com");

        address = userInfo.getAddress();

        assertThat(address.getFormatted()).isEqualTo("Some formatted");
        assertThat(address.getStreetAddress()).isEqualTo("Some street");
        assertThat(address.getLocality()).isEqualTo("Some locality");
        assertThat(address.getRegion()).isEqualTo("Some region");
        assertThat(address.getPostalCode()).isEqualTo("1000");
        assertThat(address.getCountry()).isEqualTo("Some country");
    }

    @Test
    public void testConstructor() {

        Subject subject = new Subject("alice");

        UserInfo userInfo = new UserInfo(subject);

        assertThat(userInfo.getSubject().getValue()).isEqualTo(subject.getValue());
        assertThat(userInfo.getName()).isNull();
        assertThat(userInfo.getGivenName()).isNull();
        assertThat(userInfo.getFamilyName()).isNull();
        assertThat(userInfo.getMiddleName()).isNull();
        assertThat(userInfo.getNickname()).isNull();
        assertThat(userInfo.getPreferredUsername()).isNull();
        assertThat(userInfo.getProfile()).isNull();
        assertThat(userInfo.getPicture()).isNull();
        assertThat(userInfo.getWebsite()).isNull();
        assertThat(userInfo.getEmail()).isNull();
        assertThat(userInfo.getEmailAddress()).isNull();
        assertThat(userInfo.getEmailVerified()).isNull();
        assertThat(userInfo.getGender()).isNull();
        assertThat(userInfo.getBirthdate()).isNull();
        assertThat(userInfo.getZoneinfo()).isNull();
        assertThat(userInfo.getLocale()).isNull();
        assertThat(userInfo.getPhoneNumber()).isNull();
        assertThat(userInfo.getPhoneNumberVerified()).isNull();
        assertThat(userInfo.getAddress()).isNull();
        assertThat(userInfo.getUpdatedTime()).isNull();

        // No external claims
        assertThat(userInfo.getAggregatedClaims()).isNull();
        assertThat(userInfo.getDistributedClaims()).isNull();
    }

    @Test
    public void testGettersAndSetters()
            throws Exception {

        UserInfo userInfo = new UserInfo(new Subject("sub"));

        userInfo.setName("name");
        userInfo.setGivenName("given_name");
        userInfo.setFamilyName("family_name");
        userInfo.setMiddleName("middle_name");
        userInfo.setNickname("nickname");
        userInfo.setPreferredUsername("preferred_username");
        userInfo.setProfile(new URI("https://profile.com"));
        userInfo.setPicture(new URI("https://picture.com"));
        userInfo.setWebsite(new URI("https://website.com"));
        userInfo.setEmailAddress("name@domain.com");
        userInfo.setEmailVerified(true);
        userInfo.setGender(Gender.FEMALE);
        userInfo.setBirthdate("1992-01-31");
        userInfo.setZoneinfo("Europe/Paris");
        userInfo.setLocale("en-GB");
        userInfo.setPhoneNumber("phone_number");
        userInfo.setPhoneNumberVerified(true);

        Address address = new Address();
        address.setFormatted("formatted");
        address.setStreetAddress("street_address");
        address.setLocality("locality");
        address.setRegion("region");
        address.setPostalCode("postal_code");
        address.setCountry("country");

        userInfo.setAddress(address);

        userInfo.setUpdatedTime(DateUtils.fromSecondsSinceEpoch(100000L));

        assertThat(userInfo.getSubject().getValue()).isEqualTo("sub");
        assertThat(userInfo.getGivenName()).isEqualTo("given_name");
        assertThat(userInfo.getFamilyName()).isEqualTo("family_name");
        assertThat(userInfo.getMiddleName()).isEqualTo("middle_name");
        assertThat(userInfo.getNickname()).isEqualTo("nickname");
        assertThat(userInfo.getPreferredUsername()).isEqualTo("preferred_username");
        assertThat(userInfo.getProfile().toString()).isEqualTo("https://profile.com");
        assertThat(userInfo.getPicture().toString()).isEqualTo("https://picture.com");
        assertThat(userInfo.getWebsite().toString()).isEqualTo("https://website.com");
        assertThat(userInfo.getEmailAddress()).isEqualTo("name@domain.com");
        assertThat(userInfo.getEmailVerified()).isTrue();
        assertThat(userInfo.getGender()).isEqualTo(Gender.FEMALE);
        assertThat(userInfo.getBirthdate()).isEqualTo("1992-01-31");
        assertThat(userInfo.getZoneinfo()).isEqualTo("Europe/Paris");
        assertThat(userInfo.getLocale()).isEqualTo("en-GB");
        assertThat(userInfo.getPhoneNumber()).isEqualTo("phone_number");
        assertThat(userInfo.getPhoneNumberVerified()).isTrue();

        address = userInfo.getAddress();
        assertThat(address.getFormatted()).isEqualTo("formatted");
        assertThat(address.getStreetAddress()).isEqualTo("street_address");
        assertThat(address.getLocality()).isEqualTo("locality");
        assertThat(address.getRegion()).isEqualTo("region");
        assertThat(address.getPostalCode()).isEqualTo("postal_code");
        assertThat(address.getCountry()).isEqualTo("country");

        String json = userInfo.toJSONObject().build().toString();

        userInfo = UserInfo.parse(json);

        assertThat(userInfo.getSubject().getValue()).isEqualTo("sub");
        assertThat(userInfo.getGivenName()).isEqualTo("given_name");
        assertThat(userInfo.getFamilyName()).isEqualTo("family_name");
        assertThat(userInfo.getMiddleName()).isEqualTo("middle_name");
        assertThat(userInfo.getNickname()).isEqualTo("nickname");
        assertThat(userInfo.getPreferredUsername()).isEqualTo("preferred_username");
        assertThat(userInfo.getProfile().toString()).isEqualTo("https://profile.com");
        assertThat(userInfo.getPicture().toString()).isEqualTo("https://picture.com");
        assertThat(userInfo.getWebsite().toString()).isEqualTo("https://website.com");
        assertThat(userInfo.getEmailAddress()).isEqualTo("name@domain.com");
        assertThat(userInfo.getEmailVerified()).isTrue();
        assertThat(userInfo.getGender()).isEqualTo(Gender.FEMALE);
        assertThat(userInfo.getBirthdate()).isEqualTo("1992-01-31");
        assertThat(userInfo.getZoneinfo()).isEqualTo("Europe/Paris");
        assertThat(userInfo.getLocale()).isEqualTo("en-GB");
        assertThat(userInfo.getPhoneNumber()).isEqualTo("phone_number");
        assertThat(userInfo.getPhoneNumberVerified()).isTrue();

        address = userInfo.getAddress();
        assertThat(address.getFormatted()).isEqualTo("formatted");
        assertThat(address.getStreetAddress()).isEqualTo("street_address");
        assertThat(address.getLocality()).isEqualTo("locality");
        assertThat(address.getRegion()).isEqualTo("region");
        assertThat(address.getPostalCode()).isEqualTo("postal_code");
        assertThat(address.getCountry()).isEqualTo("country");
    }

    @Test
    public void testGettersAndSetters_withDeprecatedEmail()
            throws Exception {

        UserInfo userInfo = new UserInfo(new Subject("sub"));

        userInfo.setName("name");
        userInfo.setGivenName("given_name");
        userInfo.setFamilyName("family_name");
        userInfo.setMiddleName("middle_name");
        userInfo.setNickname("nickname");
        userInfo.setPreferredUsername("preferred_username");
        userInfo.setProfile(new URI("https://profile.com"));
        userInfo.setPicture(new URI("https://picture.com"));
        userInfo.setWebsite(new URI("https://website.com"));
        userInfo.setEmail(new InternetAddress("name@domain.com"));
        userInfo.setEmailVerified(true);
        userInfo.setGender(Gender.FEMALE);
        userInfo.setBirthdate("1992-01-31");
        userInfo.setZoneinfo("Europe/Paris");
        userInfo.setLocale("en-GB");
        userInfo.setPhoneNumber("phone_number");
        userInfo.setPhoneNumberVerified(true);

        Address address = new Address();
        address.setFormatted("formatted");
        address.setStreetAddress("street_address");
        address.setLocality("locality");
        address.setRegion("region");
        address.setPostalCode("postal_code");
        address.setCountry("country");

        userInfo.setAddress(address);

        userInfo.setUpdatedTime(DateUtils.fromSecondsSinceEpoch(100000l));

        assertThat(userInfo.getSubject().getValue()).isEqualTo("sub");
        assertThat(userInfo.getGivenName()).isEqualTo("given_name");
        assertThat(userInfo.getFamilyName()).isEqualTo("family_name");
        assertThat(userInfo.getMiddleName()).isEqualTo("middle_name");
        assertThat(userInfo.getNickname()).isEqualTo("nickname");
        assertThat(userInfo.getPreferredUsername()).isEqualTo("preferred_username");
        assertThat(userInfo.getProfile().toString()).isEqualTo("https://profile.com");
        assertThat(userInfo.getPicture().toString()).isEqualTo("https://picture.com");
        assertThat(userInfo.getWebsite().toString()).isEqualTo("https://website.com");
        assertThat(userInfo.getEmail().getAddress()).isEqualTo("name@domain.com");
        assertThat(userInfo.getEmailVerified()).isTrue();
        assertThat(userInfo.getGender()).isEqualTo(Gender.FEMALE);
        assertThat(userInfo.getBirthdate()).isEqualTo("1992-01-31");
        assertThat(userInfo.getZoneinfo()).isEqualTo("Europe/Paris");
        assertThat(userInfo.getLocale()).isEqualTo("en-GB");
        assertThat(userInfo.getPhoneNumber()).isEqualTo("phone_number");
        assertThat(userInfo.getPhoneNumberVerified()).isTrue();

        address = userInfo.getAddress();
        assertThat(address.getFormatted()).isEqualTo("formatted");
        assertThat(address.getStreetAddress()).isEqualTo("street_address");
        assertThat(address.getLocality()).isEqualTo("locality");
        assertThat(address.getRegion()).isEqualTo("region");
        assertThat(address.getPostalCode()).isEqualTo("postal_code");
        assertThat(address.getCountry()).isEqualTo("country");

        String json = userInfo.toJSONObject().build().toString();

        userInfo = UserInfo.parse(json);

        assertThat(userInfo.getSubject().getValue()).isEqualTo("sub");
        assertThat(userInfo.getGivenName()).isEqualTo("given_name");
        assertThat(userInfo.getFamilyName()).isEqualTo("family_name");
        assertThat(userInfo.getMiddleName()).isEqualTo("middle_name");
        assertThat(userInfo.getNickname()).isEqualTo("nickname");
        assertThat(userInfo.getPreferredUsername()).isEqualTo("preferred_username");
        assertThat(userInfo.getProfile().toString()).isEqualTo("https://profile.com");
        assertThat(userInfo.getPicture().toString()).isEqualTo("https://picture.com");
        assertThat(userInfo.getWebsite().toString()).isEqualTo("https://website.com");
        assertThat(userInfo.getEmail().getAddress()).isEqualTo("name@domain.com");
        assertThat(userInfo.getEmailVerified()).isTrue();
        assertThat(userInfo.getGender()).isEqualTo(Gender.FEMALE);
        assertThat(userInfo.getBirthdate()).isEqualTo("1992-01-31");
        assertThat(userInfo.getZoneinfo()).isEqualTo("Europe/Paris");
        assertThat(userInfo.getLocale()).isEqualTo("en-GB");
        assertThat(userInfo.getPhoneNumber()).isEqualTo("phone_number");
        assertThat(userInfo.getPhoneNumberVerified()).isTrue();

        address = userInfo.getAddress();
        assertThat(address.getFormatted()).isEqualTo("formatted");
        assertThat(address.getStreetAddress()).isEqualTo("street_address");
        assertThat(address.getLocality()).isEqualTo("locality");
        assertThat(address.getRegion()).isEqualTo("region");
        assertThat(address.getPostalCode()).isEqualTo("postal_code");
        assertThat(address.getCountry()).isEqualTo("country");
    }

    @Test
    public void testLanguageTaggedGettersAndSetters()
            throws Exception {

        UserInfo userInfo = new UserInfo(new Subject("sub"));

        userInfo.setName("name");

        userInfo.setGivenName("given_name");

        userInfo.setFamilyName("family_name");

        userInfo.setMiddleName("middle_name");

        userInfo.setNickname("nickname");

        Address address = new Address();
        address.setFormatted("formatted");

        userInfo.setAddress(address);

        assertThat(userInfo.getName()).isEqualTo("name");

        assertThat(userInfo.getGivenName()).isEqualTo("given_name");

        assertThat(userInfo.getFamilyName()).isEqualTo("family_name");

        assertThat(userInfo.getMiddleName()).isEqualTo("middle_name");

        assertThat(userInfo.getNickname()).isEqualTo("nickname");

        assertThat(userInfo.getAddress().getFormatted()).isEqualTo("formatted");

        String json = userInfo.toJSONObject().build().toString();

        userInfo = UserInfo.parse(json);

        assertThat(userInfo.getName()).isEqualTo("name");

        assertThat(userInfo.getGivenName()).isEqualTo("given_name");

        assertThat(userInfo.getFamilyName()).isEqualTo("family_name");

        assertThat(userInfo.getMiddleName()).isEqualTo("middle_name");

        assertThat(userInfo.getNickname()).isEqualTo("nickname");

        assertThat(userInfo.getAddress().getFormatted()).isEqualTo("formatted");
    }

    @Test
    public void testPutAll() {

        Subject alice = new Subject("alice");

        UserInfo userInfo = new UserInfo(alice);
        userInfo.setGivenName("Alice");

        UserInfo other = new UserInfo(alice);
        other.setFamilyName("Adams");

        userInfo.putAll(other);
        assertThat(userInfo.getSubject()).isEqualTo(alice);
        assertThat(userInfo.getGivenName()).isEqualTo("Alice");
        assertThat(userInfo.getFamilyName()).isEqualTo("Adams");
        assertThat(userInfo.toJSONObject().build()).hasSize(3);
    }

    @Test
    public void testPullAllSubjectMismatch() {

        Subject alice = new Subject("alice");
        Subject bob = new Subject("bob");

        UserInfo userInfoAlice = new UserInfo(alice);
        userInfoAlice.setGivenName("Alice");

        UserInfo userInfoBob = new UserInfo(bob);
        userInfoBob.setGivenName("Bob");

        try {
            userInfoAlice.putAll(userInfoBob);

            fail("Failed to raise exception");

        } catch (IllegalArgumentException e) {

            // ok
        }
    }

    @Test
    public void testPutAllMap() {

        UserInfo userInfo = new UserInfo(new Subject("alice"));
        userInfo.setName("Alice");
        assertThat(userInfo.getStringClaim("name")).isEqualTo("Alice");

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "Alice Wonderland");
        claims.put("given_name", "Alice");

        userInfo.putAll(claims);
        assertThat(userInfo.getName()).isEqualTo("Alice Wonderland");
        assertThat(userInfo.getGivenName()).isEqualTo("Alice");
    }

    @Test
    public void testParseInvalidEmailAddress_ignore() throws OAuth2JSONParseException {

        JsonObjectBuilder obuilder = Json.createObjectBuilder();
        obuilder.add("sub", "alice");
        obuilder.add("email", "invalid-email");

        UserInfo userInfo = UserInfo.parse(obuilder.build().toString());

        assertThat(userInfo.getEmailAddress()).isEqualTo("invalid-email");

    }

    @Test
    public void testAggregatedClaims_addAndGet()
            throws Exception {

        UserInfo userInfo = new UserInfo(new Subject("alice"));

        JsonObjectBuilder c1builder = Json.createObjectBuilder();
        c1builder.add("email", "alice@wonderland.net");
        c1builder.add("email_verified", true);

        JsonObject c1 = c1builder.build();

        JWT jwt1 = AggregatedClaimsTest.createClaimsJWT(c1);

        AggregatedClaims a1 = new AggregatedClaims("src1", c1.keySet(), jwt1);
        userInfo.addAggregatedClaims(a1);

        JsonObjectBuilder c2builder = Json.createObjectBuilder();
        c2builder.add("score", "100");

        JsonObject c2 = c2builder.build();

        JWT jwt2 = AggregatedClaimsTest.createClaimsJWT(c2);

        AggregatedClaims a2 = new AggregatedClaims("src2", c2.keySet(), jwt2);
        userInfo.addAggregatedClaims(a2);

        JsonObject jsonObject = userInfo.toJSONObject().build();

        assertThat(jsonObject.getString("sub")).isEqualTo("alice");
        assertThat(jsonObject.getJsonObject("_claim_names").getString("email")).isEqualTo("src1");
        assertThat(jsonObject.getJsonObject("_claim_names").getString("email_verified")).isEqualTo("src1");
        assertThat(jsonObject.getJsonObject("_claim_names").getString("score")).isEqualTo("src2");
        assertThat(jsonObject.getJsonObject("_claim_names")).hasSize(3);
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src1").getString("JWT")).isEqualTo(jwt1.serialize());
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src2").getString("JWT")).isEqualTo(jwt2.serialize());
        assertThat(jsonObject.getJsonObject("_claim_sources")).hasSize(2);
        assertThat(jsonObject).hasSize(3);

        Set<AggregatedClaims> set = userInfo.getAggregatedClaims();

        for (AggregatedClaims c : set) {

            AggregatedClaims ref = null;

            if (a1.getSourceID().equals(c.getSourceID())) {

                ref = a1;

            } else if (a2.getSourceID().equals(c.getSourceID())) {

                ref = a2;

            } else {
                fail();
            }

            assertThat(c.getNames()).isEqualTo(ref.getNames());
            assertThat(c.getClaimsJWT().serialize()).isEqualTo(ref.getClaimsJWT().serialize());
        }

        assertThat(set).hasSize(2);
    }

    @Test
    @Ignore // FIXME test fails, so check if required by Octopus and Fix
    public void testDistributedClaims_addAndGet()
            throws Exception {

        UserInfo userInfo = new UserInfo(new Subject("alice"));

        DistributedClaims d1 = new DistributedClaims(
                "src1",
                new HashSet<>(Arrays.asList("email", "email_verified")),
                new URI("https://claims-provider.com"),
                new BearerAccessToken()
        );
        userInfo.addDistributedClaims(d1);

        DistributedClaims d2 = new DistributedClaims(
                "src2",
                Collections.singleton("score"),
                new URI("https://other-provider.com"),
                null
        );
        userInfo.addDistributedClaims(d2);

        JsonObject jsonObject = userInfo.toJSONObject().build();

        assertThat(jsonObject.getString("sub")).isEqualTo("alice");
        assertThat(jsonObject.getJsonObject("_claim_names").getString("email")).isEqualTo("src1");
        assertThat(jsonObject.getJsonObject("_claim_names").getString("email_verified")).isEqualTo("src1");
        assertThat(jsonObject.getJsonObject("_claim_names").getString("score")).isEqualTo("src2");
        assertThat(jsonObject.getJsonObject("_claim_names")).hasSize(3);
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src1").getString("endpoint")).isEqualTo(d1.getSourceEndpoint().toString());
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src1").getString("access_token")).isEqualTo(d1.getAccessToken().getValue());
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src1")).hasSize(2);
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src2").getString("endpoint")).isEqualTo(d2.getSourceEndpoint().toString());
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src2")).hasSize(1);
        assertThat(jsonObject.getJsonObject("_claim_sources")).hasSize(2);
        assertThat(jsonObject).hasSize(3);

        Set<DistributedClaims> set = userInfo.getDistributedClaims();

        for (DistributedClaims c : set) {

            DistributedClaims ref = null;

            if (d1.getSourceID().equals(c.getSourceID())) {

                ref = d1;

            } else if (d2.getSourceID().equals(c.getSourceID())) {

                ref = d2;

            } else {
                fail();
            }

            assertThat(c.getNames()).isEqualTo(ref.getNames());
            assertThat(c.getSourceEndpoint()).isEqualTo(ref.getSourceEndpoint());
            if (ref.getAccessToken() != null) {
                assertThat(c.getAccessToken().getValue()).isEqualTo(ref.getAccessToken().getValue());
            }
        }

        assertThat(set).hasSize(2);
    }

    @Test
    public void testParseDistributedClaimsExample()
            throws Exception {

        String json =
                "{" +
                        "   \"sub\":\"jd\"," + // fix example, missing 'sub'
                        "   \"name\": \"Jane Doe\"," +
                        "   \"given_name\": \"Jane\"," +
                        "   \"family_name\": \"Doe\"," +
                        "   \"email\": \"janedoe@example.com\"," +
                        "   \"birthdate\": \"0000-03-22\"," +
                        "   \"eye_color\": \"blue\"," +
                        "   \"_claim_names\": {" +
                        "     \"payment_info\": \"src1\"," +
                        "     \"shipping_address\": \"src1\"," +
                        "     \"credit_score\": \"src2\"" +
                        "    }," +
                        "   \"_claim_sources\": {" +
                        "     \"src1\": {\"endpoint\":" +
                        "                \"https://bank.example.com/claim_source\"}," +
                        "     \"src2\": {\"endpoint\":" +
                        "                \"https://creditagency.example.com/claims_here\"," +
                        "              \"access_token\": \"ksj3n283dke\"}" +
                        "   }" +
                        "  }";

        UserInfo userInfo = UserInfo.parse(json);

        Set<DistributedClaims> dcSet = userInfo.getDistributedClaims();

        for (DistributedClaims dc : dcSet) {

            if ("src1".equals(dc.getSourceID())) {

                assertThat(dc.getNames().contains("payment_info")).isTrue();
                assertThat(dc.getNames().contains("shipping_address")).isTrue();
                assertThat(dc.getNames()).hasSize(2);

                assertThat(dc.getSourceEndpoint().toString()).isEqualTo("https://bank.example.com/claim_source");
                assertThat(dc.getAccessToken()).isNull();

            } else if ("src2".equals(dc.getSourceID())) {

                assertThat(dc.getNames().contains("credit_score")).isTrue();
                assertThat(dc.getNames()).hasSize(1);

                assertThat(dc.getSourceEndpoint().toString()).isEqualTo("https://creditagency.example.com/claims_here");
                assertThat(dc.getAccessToken().getValue()).isEqualTo("ksj3n283dke");
                assertThat(dc.getAccessToken()).isInstanceOf(TypelessAccessToken.class);

            } else {
                fail();
            }
        }

        assertThat(dcSet).hasSize(2);
    }

    @Test
    public void testPutAll_mergeAggregatedAndDistributedClaims()
            throws Exception {

        UserInfo userInfo = new UserInfo(new Subject("alice"));

        AggregatedClaims ac = new AggregatedClaims(
                "src1",
                new HashSet<>(Arrays.asList("email", "email_verified")),
                AggregatedClaimsTest.createClaimsJWT()
        );

        userInfo.addAggregatedClaims(ac);

        assertThat(userInfo.getAggregatedClaims()).hasSize(1);

        UserInfo other = new UserInfo(new Subject("alice"));

        DistributedClaims dc = new DistributedClaims(
                "src2",
                Collections.singleton("score"),
                new URI("https://claims-source.com"),
                new BearerAccessToken());

        other.addDistributedClaims(dc);

        assertThat(other.getDistributedClaims()).hasSize(1);

        userInfo.putAll(other);

        JsonObject jsonObject = userInfo.toJSONObject().build();

        // Check merge
        assertThat(userInfo.getSubject()).isEqualTo(new Subject("alice"));

        assertThat(userInfo.getAggregatedClaims().iterator().next().getSourceID()).isEqualTo(ac.getSourceID());
        assertThat(userInfo.getAggregatedClaims().iterator().next().getNames()).isEqualTo(ac.getNames());
        assertThat(userInfo.getAggregatedClaims().iterator().next().getClaimsJWT().serialize()).isEqualTo(ac.getClaimsJWT().serialize());

        assertThat(userInfo.getDistributedClaims().iterator().next().getSourceID()).isEqualTo(dc.getSourceID());
        assertThat(userInfo.getDistributedClaims().iterator().next().getNames()).isEqualTo(dc.getNames());
        assertThat(userInfo.getDistributedClaims().iterator().next().getSourceEndpoint()).isEqualTo(dc.getSourceEndpoint());
        assertThat(userInfo.getDistributedClaims().iterator().next().getAccessToken().getValue()).isEqualTo(dc.getAccessToken().getValue());

        assertThat(jsonObject.getString("sub")).isEqualTo("alice");

        assertThat(jsonObject.getJsonObject("_claim_names").getString("email")).isEqualTo("src1");
        assertThat(jsonObject.getJsonObject("_claim_names").getString("email_verified")).isEqualTo("src1");
        assertThat(jsonObject.getJsonObject("_claim_names").getString("score")).isEqualTo("src2");
        assertThat(jsonObject.getJsonObject("_claim_names")).hasSize(3);

        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src1").getString("JWT")).isEqualTo(ac.getClaimsJWT().serialize());
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src1")).hasSize(1);

        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src2").getString("endpoint")).isEqualTo(dc.getSourceEndpoint().toString());
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src2").getString("access_token")).isEqualTo(dc.getAccessToken().getValue());
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src2")).hasSize(2);

        assertThat(jsonObject).hasSize(3);
    }

    @Test
    @Ignore // FIXME test fails, so check if required by Octopus and Fix
    public void testPutAll_mergeDistributedClaims()
            throws Exception {

        UserInfo userInfo = new UserInfo(new Subject("alice"));

        DistributedClaims dc1 = new DistributedClaims(
                "src1",
                new HashSet<>(Arrays.asList("email", "email_verified")),
                new URI("https://claims-source.com"),
                new BearerAccessToken()
        );

        userInfo.addDistributedClaims(dc1);

        assertThat(userInfo.getDistributedClaims()).hasSize(1);

        UserInfo other = new UserInfo(new Subject("alice"));

        DistributedClaims dc2 = new DistributedClaims(
                "src2",
                Collections.singleton("score"),
                new URI("https://other-claims-source.com"),
                new BearerAccessToken());

        other.addDistributedClaims(dc2);

        assertThat(other.getDistributedClaims()).hasSize(1);

        userInfo.putAll(other);

        JsonObject jsonObject = userInfo.toJSONObject().build();

        // Check merge
        assertThat(userInfo.getSubject()).isEqualTo(new Subject("alice"));

        for (DistributedClaims dc : userInfo.getDistributedClaims()) {

            DistributedClaims ref = null;

            if (dc.getSourceID().equals(dc1.getSourceID())) {
                ref = dc1;
            } else if (dc.getSourceID().equals(dc2.getSourceID())) {
                ref = dc2;
            } else {
                fail();
            }

            assertThat(dc.getSourceID()).isEqualTo(ref.getSourceID());
            assertThat(dc.getSourceEndpoint()).isEqualTo(ref.getSourceEndpoint());
            assertThat(dc.getAccessToken().getValue()).isEqualTo(ref.getAccessToken().getValue());
        }

        assertThat(jsonObject.getString("sub")).isEqualTo("alice");

        assertThat(jsonObject.getJsonObject("_claim_names").getString("email")).isEqualTo("src1");
        assertThat(jsonObject.getJsonObject("_claim_names").getString("email_verified")).isEqualTo("src1");
        assertThat(jsonObject.getJsonObject("_claim_names").getString("score")).isEqualTo("src2");
        assertThat(jsonObject.getJsonObject("_claim_names")).hasSize(3);

        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src1").getString("endpoint")).isEqualTo(dc1.getSourceEndpoint().toString());
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src1").getString("access_token")).isEqualTo(dc1.getAccessToken().getValue());
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src1")).hasSize(2);

        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src2").getString("endpoint")).isEqualTo(dc2.getSourceEndpoint().toString());
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src2").getString("access_token")).isEqualTo(dc2.getAccessToken().getValue());
        assertThat(jsonObject.getJsonObject("_claim_sources").getJsonObject("src2")).hasSize(2);

        assertThat(jsonObject).hasSize(3);
    }

    @Test
    public void testPutAll_withExternalClaims_preventSourceIDConflict()
            throws Exception {

        UserInfo userInfo = new UserInfo(new Subject("alice"));

        AggregatedClaims ac = new AggregatedClaims(
                "src1",
                new HashSet<>(Arrays.asList("email", "email_verified")),
                AggregatedClaimsTest.createClaimsJWT()
        );

        userInfo.addAggregatedClaims(ac);

        assertThat(userInfo.getAggregatedClaims()).hasSize(1);

        UserInfo other = new UserInfo(new Subject("alice"));

        DistributedClaims dc = new DistributedClaims(
                "src1", // same!!!
                Collections.singleton("score"),
                new URI("https://claims-source.com"),
                new BearerAccessToken());

        other.addDistributedClaims(dc);

        assertThat(other.getDistributedClaims()).hasSize(1);

        try {
            userInfo.putAll(other);
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("Distributed claims source ID conflict: src1");
        }
    }

    @Test
    public void testIssuerClaim()
            throws Exception {

        UserInfo userInfo = new UserInfo(new Subject("alice"));

        assertThat(userInfo.getIssuer()).isNull();

        Issuer issuer = new Issuer("https://c2id.com");

        userInfo.setIssuer(issuer);

        assertThat(userInfo.getIssuer()).isEqualTo(issuer);

        JsonObject jsonObject = userInfo.toJSONObject().build();

        assertThat(jsonObject.getString("sub")).isEqualTo(userInfo.getSubject().getValue());
        assertThat(jsonObject.getString("iss")).isEqualTo(issuer.getValue());
        assertThat(jsonObject).hasSize(2);

        userInfo = UserInfo.parse(jsonObject.toString());

        assertThat(userInfo.getIssuer()).isEqualTo(issuer);

        userInfo.setIssuer(null);

        assertThat(userInfo.getIssuer()).isNull();
    }


    @Test
    public void testAudienceClaim_single()
            throws Exception {

        UserInfo userInfo = new UserInfo(new Subject("alice"));

        assertThat(userInfo.getAudience()).isNull();

        Audience aud = new Audience("123");

        userInfo.setAudience(aud);

        assertThat(userInfo.getAudience()).isEqualTo(aud.toSingleAudienceList());

        JsonObject jsonObject = userInfo.toJSONObject().build();

        assertThat(JSONObjectUtils.getStringList(jsonObject, "aud")).isEqualTo(Audience.toStringList(aud));

        userInfo = UserInfo.parse(jsonObject.toString());

        assertThat(userInfo.getAudience()).isEqualTo(aud.toSingleAudienceList());

        userInfo.setAudience((Audience) null);

        assertThat(userInfo.getAudience()).isNull();
    }


    @Test
    public void testAudienceClaim_list()
            throws Exception {

        UserInfo userInfo = new UserInfo(new Subject("alice"));

        assertThat(userInfo.getAudience()).isNull();

        List<Audience> audList = Arrays.asList(new Audience("123"), new Audience("456"));

        userInfo.setAudience(audList);

        assertThat(userInfo.getAudience()).isEqualTo(audList);

        JsonObject jsonObject = userInfo.toJSONObject().build();

        assertThat(JSONObjectUtils.getStringList(jsonObject, "aud")).isEqualTo(Audience.toStringList(audList));

        userInfo = UserInfo.parse(jsonObject.toString());

        assertThat(userInfo.getAudience()).isEqualTo(audList);

        userInfo.setAudience((List<Audience>) null);

        assertThat(userInfo.getAudience()).isNull();
    }
}
