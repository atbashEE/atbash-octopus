/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.realm;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.SimpleAuthenticationInfo;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.util.codec.ByteSource;
import be.atbash.ee.security.octopus.util.codec.SimpleByteSource;

import javax.enterprise.inject.Typed;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@Typed
public class AuthenticationInfoBuilder {

    private Serializable principalId;
    private String name;
    private String userName;
    private Object password;
    private ByteSource salt;
    private Map<Serializable, Serializable> userInfo = new HashMap<>();
    private boolean externalPasswordCheck = false;

    public AuthenticationInfoBuilder principalId(Serializable principalId) {
        this.principalId = principalId;
        return this;
    }

    public AuthenticationInfoBuilder name(String name) {
        this.name = name;
        return this;
    }

    public AuthenticationInfoBuilder userName(String userName) {
        this.userName = userName;
        return this;
    }

    public AuthenticationInfoBuilder password(Object password) {
        this.password = password;
        return this;

    }

    public AuthenticationInfoBuilder salt(ByteSource salt) {
        this.salt = salt;
        return this;
    }

    public AuthenticationInfoBuilder salt(byte[] salt) {
        salt(new SimpleByteSource(salt));
        return this;
    }

    public AuthenticationInfoBuilder externalPasswordCheck() {
        externalPasswordCheck = true;
        return this;
    }

    public AuthenticationInfoBuilder addUserInfo(Serializable key, Serializable value) {
        userInfo.put(key, value);
        return this;
    }

    public AuthenticationInfoBuilder addUserInfo(Map<? extends Serializable, ? extends Serializable> values) {
        userInfo.putAll(values);
        return this;
    }

    public AuthenticationInfo build() {
        UserPrincipal principal = new UserPrincipal(principalId, userName, name);
        principal.addUserInfo(userInfo);
        AuthenticationInfo result;
        // TODO We need to check if developer supplied salt() when octopusConfig.saltLength != 0
        if (salt == null) {
            if (externalPasswordCheck) {
                //result = new ExternalPasswordAuthenticationInfo(principal);
                result = null; // FIXME
            } else {
                result = new SimpleAuthenticationInfo(principal, password);
            }
        } else {
            result = new SimpleAuthenticationInfo(principal, password, salt);
        }
        return result;
    }

}
