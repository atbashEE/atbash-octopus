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
package be.atbash.ee.security.octopus.cas.adapter;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.authz.TokenBasedAuthorizationInfoProvider;
import be.atbash.ee.security.octopus.token.AbstractOctopusAuthenticationToken;
import be.atbash.ee.security.octopus.token.AuthorizationToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class CasUserToken extends AbstractOctopusAuthenticationToken implements ValidatedAuthenticationToken, AuthorizationToken {

    public static final String CAS_USER_INFO = "CASUserInfo";

    private String ticket;
    private String userName;
    private String email;
    private Map<String, Serializable> userInfo;

    public CasUserToken(String ticket) {
        this.ticket = ticket;
    }

    public String getTicket() {
        return ticket;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserName() {
        return userName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public Map<String, Serializable> getUserInfo() {
        Map<String, Serializable> result = new HashMap<>(userInfo);
        result.put(OctopusConstants.UPSTREAM_TOKEN, ticket);

        return result;
    }

    public void setUserInfo(Map<String, Serializable> userInfo) {
        this.userInfo = userInfo;
    }

    @Override
    public Object getPrincipal() {
        return new CasPrincipal(userName, email);
    }

    @Override
    public Object getCredentials() {
        return ticket;
    }

    @Override
    public String getName() {
        return userName;
    }

    @Override
    public Class<? extends TokenBasedAuthorizationInfoProvider> authorizationProviderClass() {
        return CasUserTokenAuthorizationProvider.class;
    }

    public static class CasPrincipal {
        private String id;
        private String email;

        public CasPrincipal(String id, String email) {
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
            if (!(o instanceof CasPrincipal)) {
                return false;
            }

            CasPrincipal that = (CasPrincipal) o;

            if (!id.equals(that.id)) {
                return false;
            }
            return Objects.equals(email, that.email);

        }

        @Override
        public int hashCode() {
            int result = id.hashCode();
            result = 31 * result + (email != null ? email.hashCode() : 0);
            return result;
        }
    }
}
