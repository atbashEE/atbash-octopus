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
package be.atbash.ee.security.octopus.subject;

import be.atbash.util.exception.AtbashIllegalActionException;

import javax.enterprise.inject.Typed;
import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@Typed
public class UserPrincipal implements Principal, Serializable {

    private Serializable id;
    private String userName;
    private String name;
    private boolean systemAccount = false;

    private Map<Serializable, Serializable> userInfo = new HashMap<>();

    // Weld needs this to make a proxy
    public UserPrincipal() {
    }

    /**
     * Regular creation of the user principal for a user which has identified itself.
     *
     * @param id       unique id of the user.
     * @param userName The user name.
     * @param name     The name.
     */
    public UserPrincipal(Serializable id, String userName, String name) {
        if (id == null) {
            throw new IllegalArgumentException("id cannot be null");
        }
        this.id = id;
        this.userName = userName;
        this.name = name;
    }

    /**
     * Creation of the user principal for a system account.
     *
     * @param systemAccountName The system account name.
     */
    public UserPrincipal(String systemAccountName) {
        this(systemAccountName, systemAccountName, systemAccountName);
        systemAccount = true;
    }

    public Serializable getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        if (this.name != null) {
            throw new AtbashIllegalActionException("(OCT-DEV-001) Setting the name of the Principal isn't allowed since there is already a name specified");
        }
        this.name = name;
    }

    public String getUserName() {
        return userName;
    }

    public void addUserInfo(Serializable key, Serializable value) {
        userInfo.put(key, value);
    }

    public void addUserInfo(Map<? extends Serializable, ? extends Serializable> values) {
        userInfo.putAll(values);
    }

    public <T> T getUserInfo(Serializable key) {
        return (T) userInfo.get(key);
    }

    public Map<Serializable, Serializable> getInfo() {
        return userInfo;
    }

    public boolean isSystemAccount() {
        return systemAccount;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UserPrincipal)) {
            return false;
        }

        UserPrincipal that = (UserPrincipal) o;

        if (!id.equals(that.getId())) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public String toString() {
        return name;
    }
}
