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
package be.atbash.ee.security.octopus.subject;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.authc.RemoteLogoutHandler;
import be.atbash.ee.security.octopus.util.onlyduring.TemporaryAuthorizationContextManager;
import be.atbash.ee.security.octopus.util.onlyduring.WrongExecutionContextException;
import be.atbash.util.exception.AtbashIllegalActionException;

import javax.enterprise.inject.Typed;
import java.io.Serializable;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Should never be created by the developer directly, only reading the information
 */
@Typed
// @PublicAPI
public class UserPrincipal implements Principal, Serializable {

    private Serializable id;
    private String userName;
    private String name;
    private boolean systemAccount = false;
    private RemoteLogoutHandler remoteLogoutHandler;

    private Map<String, Serializable> userInfo = new HashMap<>();

    // Weld needs this to make a proxy
    // TODO Try to remove it, because it doesn't set the id and it is used for example within hashCode
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
            throw new AtbashIllegalActionException("(OCT-DEV-004) principalId cannot be null");
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
    protected UserPrincipal(String systemAccountName) {
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

    // TODO Should we protect the 'Octopus used keys', like Token?
    public void addUserInfo(String key, Serializable value) {
        // FIXME Check if the internal type of keys start with 'octopus.'
        if (key.startsWith("octopus.") && !TemporaryAuthorizationContextManager.isInAuthentication()) {
            throw new WrongExecutionContextException();
        }
        userInfo.put(key, value);
    }

    public void addUserInfo(Map<String, ? extends Serializable> values) {
        userInfo.putAll(values);
    }

    public <T> T getUserInfo(String key) {
        return (T) userInfo.get(key);
    }

    public Map<String, Serializable> getInfo() {
        // So that we never can change the info from outside this class.
        return Collections.unmodifiableMap(userInfo);
    }

    public boolean isSystemAccount() {
        return systemAccount;
    }

    /**
     * Stores the {@code RemoteLogoutHandler} which needs to be executed when this userPrincipal
     * is logged out. Used in specific scenarios to notify the original authenticator (Keycloak in the Java SE case, for example)
     * that user is logged out.
     *
     * @param remoteLogoutHandler
     */
    public void setRemoteLogoutHandler(RemoteLogoutHandler remoteLogoutHandler) {
        this.remoteLogoutHandler = remoteLogoutHandler;
    }

    public void onLogout(PrincipalCollection principals) {
        if (remoteLogoutHandler != null) {
            remoteLogoutHandler.onLogout(principals);
        }
    }

    public String getLocalId() {
        return getUserInfo(OctopusConstants.LOCAL_ID);
    }

    public String getExternalId() {
        return getUserInfo(OctopusConstants.EXTERNAL_ID);
    }

    public String getFirstName() {
        return getUserInfo(OctopusConstants.FIRST_NAME);
    }

    public String getLastName() {
        return getUserInfo(OctopusConstants.LAST_NAME);
    }

    public String getEmail() {
        return getUserInfo(OctopusConstants.EMAIL);
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
