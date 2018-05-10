/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.keycloak.adapter;

import be.atbash.ee.security.octopus.OctopusConstants;
import org.junit.Test;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class KeycloakUserTokenTest {

    @Test
    public void fromIdToken() {
        IDToken token = new IDToken();

        token.id("id");
        token.setName("name");
        token.setGivenName("Given name");
        token.setFamilyName("Family name");

        token.setEmail("Email");

        token.setGender("Gender");
        token.setLocale("nl");
        token.setPicture("picture");

        AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
        accessTokenResponse.setToken("accessToken");

        KeycloakUserToken userToken = KeycloakUserToken.fromIdToken(accessTokenResponse, token);

        assertThat(userToken).isNotNull();
        assertThat(userToken.getName()).isEqualTo("name");
        assertThat(userToken.getFullName()).isEqualTo("name");
        assertThat(userToken.getFirstName()).isEqualTo("Given name");
        assertThat(userToken.getLastName()).isEqualTo("Family name");

        assertThat(userToken.getEmail()).isEqualTo("Email");
        assertThat(userToken.getGender()).isEqualTo("Gender");
        assertThat(userToken.getLocale()).isEqualTo("nl");
        assertThat(userToken.getPicture()).isEqualTo("picture");

        assertThat(userToken.getAccessToken()).isEqualTo("accessToken");

        assertThat(userToken.getUserInfo()).hasSize(5);
        assertThat(userToken.getUserInfo().keySet()).containsOnly(OctopusConstants.EMAIL, OctopusConstants.PICTURE, OctopusConstants.GENDER, OctopusConstants.LOCALE, OctopusConstants.UPSTREAM_TOKEN);

        assertThat(userToken.getUserInfo().get(OctopusConstants.EMAIL)).isEqualTo("Email");
        assertThat(userToken.getUserInfo().get(OctopusConstants.PICTURE)).isEqualTo("picture");
        assertThat(userToken.getUserInfo().get(OctopusConstants.GENDER)).isEqualTo("Gender");
        assertThat(userToken.getUserInfo().get(OctopusConstants.LOCALE)).isEqualTo("nl");
        assertThat(userToken.getUserInfo().get(OctopusConstants.UPSTREAM_TOKEN)).isEqualTo("accessToken");

    }
}