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
package be.atbash.ee.security.octopus.oauth2;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.token.AbstractOctopusAuthenticationToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.util.PublicAPI;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.Token;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * FIXME Must this be split off in something common between JSF and Rest support for OAuth2??
 */
@PublicAPI
public class OAuth2UserToken extends AbstractOctopusAuthenticationToken implements ValidatedAuthenticationToken {

    public static final String OAUTH2_USER_INFO = "oAuth2UserInfo";

    private String id;

    private String localId;

    private String lastName;

    private String picture;

    private String gender;

    private String locale;

    private String email;

    private String link;

    private String firstName;

    private String domain;

    private boolean verifiedEmail;  // Needs to become properties

    private OAuth2AccessToken token;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getLocalId() {
        return localId;
    }

    public void setLocalId(String localId) {
        this.localId = localId;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public boolean isVerifiedEmail() {
        return verifiedEmail;
    }

    public void setVerifiedEmail(boolean verifiedEmail) {
        this.verifiedEmail = verifiedEmail;
    }

    // FIXME Required? When an instance is created, it means it is for an authenticated user.
    public boolean isLoggedOn() {
        return id != null;
    }

    public Token getToken() {
        return token;
    }

    public void setToken(OAuth2AccessToken token) {
        this.token = token;
    }

    public Map<String, Serializable> getUserInfo() {
        Map<String, Serializable> result = new HashMap<>();

        result.put(OctopusConstants.EMAIL, email);
        result.put(OctopusConstants.FIRST_NAME, firstName);
        result.put(OctopusConstants.LAST_NAME, lastName);
        result.put(OctopusConstants.PICTURE, picture);
        result.put(OctopusConstants.GENDER, gender);
        result.put(OctopusConstants.DOMAIN, domain);
        result.put(OctopusConstants.LOCALE, locale);
        if (token != null) {
            result.put(OctopusConstants.UPSTREAM_TOKEN, token.getAccessToken());
            result.put(OctopusConstants.OAUTH2_TOKEN, token);
        }
        result.putAll(userInfo);

        return result;
    }

    @Override
    public String toString() {
        return "OAuth2UserToken{" + "id='" + id + '\'' +
                ", lastName='" + lastName + '\'' +
                ", fullName='" + fullName + '\'' +
                ", picture='" + picture + '\'' +
                ", gender='" + gender + '\'' +
                ", email='" + email + '\'' +
                ", link='" + link + '\'' +
                ", firstName='" + firstName + '\'' +
                ", domain='" + domain + '\'' +
                ", verifiedEmail=" + verifiedEmail +
                '}';
    }

    @Override
    public Object getPrincipal() {
        return new OAuth2Principal(id, email);
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    // FIXME review usage
    public static class OAuth2Principal {
        private String id;
        private String email;

        OAuth2Principal(String id, String email) {
            this.id = id;
            this.email = email;
        }

        public String getId() {
            return id;
        }

        public String getEmail() {
            return email;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof OAuth2Principal)) {
                return false;
            }

            OAuth2Principal that = (OAuth2Principal) o;

            return Objects.equals(id, that.id);
        }

        @Override
        public int hashCode() {
            return id != null ? id.hashCode() : 0;
        }
    }
}
