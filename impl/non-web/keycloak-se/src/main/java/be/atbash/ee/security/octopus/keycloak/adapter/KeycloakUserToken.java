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
import be.atbash.ee.security.octopus.authz.TokenBasedAuthorizationInfoProvider;
import be.atbash.ee.security.octopus.token.AbstractOctopusAuthenticationToken;
import be.atbash.ee.security.octopus.token.AuthorizationToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.util.PublicAPI;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

import javax.security.auth.Subject;
import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 *
 */
@PublicAPI
public class KeycloakUserToken extends AbstractOctopusAuthenticationToken implements ValidatedAuthenticationToken, AuthorizationToken {

    private String id;

    private String localId;

    private String lastName;

    private String picture;

    private String gender;

    private String locale;

    private String email;

    private String firstName;

    private AccessTokenResponse accessTokenResponse;

    private String clientSession;

    private Set<String> roles = new HashSet<>();

    private KeycloakUserToken(AccessTokenResponse accessTokenResponse) {
        if (accessTokenResponse == null) {
            throw new AtbashUnexpectedException("AccessTokenResponse can't be null");
        }
        this.accessTokenResponse = accessTokenResponse;
    }

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

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getAccessToken() {
        return accessTokenResponse.getToken();
    }

    public AccessTokenResponse getAccessTokenResponse() {
        return accessTokenResponse;
    }

    public String getClientSession() {
        return clientSession;
    }

    public void setClientSession(String clientSession) {
        this.clientSession = clientSession;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public Map<String, Serializable> getUserInfo() {
        // FIXME, when calling getUserInfo(String), it doesn't include these values :(
        Map<String, Serializable> result = new HashMap<>();

        result.put(OctopusConstants.EMAIL, email);
        result.put(OctopusConstants.PICTURE, picture);
        result.put(OctopusConstants.GENDER, gender);
        result.put(OctopusConstants.LOCALE, locale);
        result.put(OctopusConstants.UPSTREAM_TOKEN, accessTokenResponse.getToken());

        result.putAll(userInfo);

        return result;
    }

    @Override
    public String toString() {
        return "KeycloakUser{" + "id='" + id + '\'' +
                ", lastName='" + lastName + '\'' +
                ", fullName='" + fullName + '\'' +
                ", picture='" + picture + '\'' +
                ", gender='" + gender + '\'' +
                ", email='" + email + '\'' +
                ", firstName='" + firstName + '\'' +
                '}';
    }

    @Override
    public String getName() {
        return fullName;
    }

    public boolean implies(Subject subject) {
        if (subject == null) {
            return false;
        }
        return subject.getPrincipals().contains(this);
    }

    @Override
    public Object getPrincipal() {
        return new KeycloakPrincipal(id, email);
    }

    @Override
    public Object getCredentials() {
        return accessTokenResponse;
    }

    @Override
    public Class<? extends TokenBasedAuthorizationInfoProvider> authorizationProviderClass() {
        return KeycloakUserTokenAuthorizationProvider.class;
    }

    static KeycloakUserToken fromIdToken(AccessTokenResponse accessTokenResponse, IDToken token) {
        KeycloakUserToken result = new KeycloakUserToken(accessTokenResponse);
        result.setId(token.getId());
        result.setFullName(token.getName());
        result.setFirstName(token.getGivenName());
        result.setLastName(token.getFamilyName());

        result.setEmail(token.getEmail());

        result.setGender(token.getGender());
        result.setLocale(token.getLocale());
        result.setPicture(token.getPicture());

        return result;
    }

    public static class KeycloakPrincipal {
        private String id;
        private String email;

        KeycloakPrincipal(String id, String email) {
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
            if (!(o instanceof KeycloakPrincipal)) {
                return false;
            }

            KeycloakPrincipal that = (KeycloakPrincipal) o;

            if (!id.equals(that.id)) {
                return false;
            }
            return email != null ? email.equals(that.email) : that.email == null;
        }

        @Override
        public int hashCode() {
            int result = id.hashCode();
            result = 31 * result + (email != null ? email.hashCode() : 0);
            return result;
        }
    }

}
