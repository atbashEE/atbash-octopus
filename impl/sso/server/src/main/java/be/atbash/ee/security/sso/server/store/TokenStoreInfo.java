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
package be.atbash.ee.security.sso.server.store;

import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.security.octopus.subject.UserPrincipal;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 */

public class TokenStoreInfo implements Serializable {


    private UserPrincipal userPrincipal;

    private String cookieToken;

    private String userAgent;
    private String remoteHost;

    private List<OIDCStoreData> oidcStoreData;

    public TokenStoreInfo(UserPrincipal userPrincipal, String cookieToken, String userAgent, String remoteHost) {
        this.userPrincipal = userPrincipal;

        this.cookieToken = cookieToken;
        this.userAgent = userAgent;
        this.remoteHost = remoteHost;

        oidcStoreData = new ArrayList<>();
    }

    public UserPrincipal getUserPrincipal() {
        return userPrincipal;
    }

    private Set<String> getClientIds() {
        Set<String> result = new HashSet<>();

        for (OIDCStoreData oidcStoreDatum : oidcStoreData) {
            ClientID clientId = oidcStoreDatum.getClientId();
            if (clientId != null) {
                result.add(clientId.getValue());
            } else {
                result.add(null);
            }
        }
        return result;
    }

    public void addOIDCStoreData(OIDCStoreData oidcStoreData) {

        OIDCStoreData existingData = findOIDCStoreData(oidcStoreData.getClientId());
        this.oidcStoreData.remove(existingData);
        this.oidcStoreData.add(oidcStoreData);
    }

    private OIDCStoreData findOIDCStoreData(ClientID clientID) {
        OIDCStoreData result = null;
        for (OIDCStoreData oidcStoreDatum : oidcStoreData) {
            if (areClientIdsEqual(clientID, oidcStoreDatum)) {
                result = oidcStoreDatum;
            }
        }
        return result;
    }

    private boolean areClientIdsEqual(ClientID clientID, OIDCStoreData oidcStoreDatum) {
        boolean result = false;
        if (clientID == null && oidcStoreDatum.getClientId() == null) {
            result = true;
        }
        if (clientID != null) {
            result = clientID.equals(oidcStoreDatum.getClientId());
        }
        return result;
    }

    public OIDCStoreData findOIDCStoreData(String accessCode) {
        OIDCStoreData result = null;
        for (OIDCStoreData oidcStoreDatum : oidcStoreData) {
            if (accessCode.equals(oidcStoreDatum.getAccessToken().getValue())) {
                result = oidcStoreDatum;
            }
        }
        return result;
    }

    public List<OIDCStoreData> getOidcStoreData() {
        return oidcStoreData;
    }

    public String getCookieToken() {
        return cookieToken;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getRemoteHost() {
        return remoteHost;
    }

    @Override
    public String toString() {
        return "TokenStoreInfo{" +
                "userPrincipal=" + userPrincipal +
                ", clientIds=" + clientIdsLogValue() +
                ", cookieToken='" + cookieToken + '\'' +
                ", userAgent='" + userAgent + '\'' +
                ", remoteHost='" + remoteHost + '\'' +
                '}';
    }

    private String clientIdsLogValue() {

        StringBuilder result = new StringBuilder();
        for (String clientId : getClientIds()) {
            if (result.length() > 0) {
                result.append(", ");
            }
            result.append(clientId);
        }
        return result.toString();
    }
}
