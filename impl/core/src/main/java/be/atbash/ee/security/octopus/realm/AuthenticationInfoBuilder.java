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
package be.atbash.ee.security.octopus.realm;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.RemoteLogoutHandler;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.util.codec.ByteSource;
import be.atbash.util.exception.AtbashIllegalActionException;

import javax.enterprise.inject.Typed;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@Typed
//@PublicAPI But need to review the usage of External password verification and the Object hierarchy of AuthenticationInfo
public class AuthenticationInfoBuilder {

    private Serializable principalId;
    private String name;
    private String userName;
    private Object password;
    private ValidatedAuthenticationToken token;
    private ByteSource salt;
    private UserPrincipal userPrincipal;
    private Map<Serializable, Serializable> userInfo = new HashMap<>();
    private boolean externalPasswordCheck = false;
    private boolean tokenBased = false;
    private RemoteLogoutHandler remoteLogoutHandler;

    public AuthenticationInfoBuilder principalId(Serializable principalId) {
        if (principalId == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-004) principalId cannot be null");
        }
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

    public AuthenticationInfoBuilder userPrincipal(UserPrincipal userPrincipal) {
        this.userPrincipal = userPrincipal;
        return this;
    }

    public AuthenticationInfoBuilder password(Object password) {
        if (password == null) {
            return this;
        }
        if (token != null) {
            throw new AtbashIllegalActionException("(OCT-DEV-003) Defining a token is not allowed when a password value is already specified.");
        }

        this.password = password;
        return this;

    }

    public AuthenticationInfoBuilder salt(ByteSource salt) {
        this.salt = salt;
        return this;
    }

    public AuthenticationInfoBuilder salt(byte[] salt) {
        salt(ByteSource.creator.bytes(salt));
        return this;
    }

    public AuthenticationInfoBuilder externalPasswordCheck() {
        externalPasswordCheck = true;
        return this;
    }

    public AuthenticationInfoBuilder token(ValidatedAuthenticationToken token) {
        if (token == null) {
            return this;
        }
        if (password != null) {
            throw new AtbashIllegalActionException("(OCT-DEV-002) Defining a token is not allowed when a password value is already specified.");
        }
        this.token = token;
        tokenBased = true;
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

    public AuthenticationInfoBuilder withRemoteLogoutHandler(RemoteLogoutHandler remoteLogoutHandler) {
        this.remoteLogoutHandler = remoteLogoutHandler;
        return this;
    }

    public AuthenticationInfo build() {
        if (userPrincipal == null) {
            userPrincipal = new UserPrincipal(principalId, userName, name);
        }
        userPrincipal.addUserInfo(userInfo);
        userPrincipal.setRemoteLogoutHandler(remoteLogoutHandler);
        AuthenticationInfo result;
        // TODO We need to check if developer supplied salt() when octopusConfig.saltLength != 0
        if (salt == null) {
            if (externalPasswordCheck) {
                //result = new ExternalPasswordAuthenticationInfo(principal);
                result = null; // FIXME
            } else {
                if (tokenBased) {
                    result = new AuthenticationInfo(userPrincipal, token);
                } else {
                    result = new AuthenticationInfo(userPrincipal, password);
                }
            }
        } else {
            result = new AuthenticationInfo(userPrincipal, password, salt);
        }
        return result;
    }

}
