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

import be.atbash.ee.security.sso.server.TimeUtil;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import net.minidev.json.JSONObject;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 *
 */

public class OIDCStoreData implements Serializable {

    private ClientID clientId;
    private Scope scope;

    private AuthorizationCode authorizationCode;
    private BearerAccessToken accessToken;
    private JSONObject idTokenClaimsSet;

    private Date expiresOn;

    public OIDCStoreData(BearerAccessToken accessToken) {
        this.accessToken = accessToken;
        expiresOn = TimeUtil.getInstance().addSecondsToDate(accessToken.getLifetime(), new Date());
        scope = accessToken.getScope();
    }

    public ClientID getClientId() {
        return clientId;
    }

    public void setClientId(ClientID clientId) {
        this.clientId = clientId;
    }

    public Scope getScope() {
        return scope;
    }

    public void setScope(Scope scope) {
        this.scope = scope;
    }

    public AuthorizationCode getAuthorizationCode() {
        return authorizationCode;
    }

    public void setAuthorizationCode(AuthorizationCode authorizationCode) {
        this.authorizationCode = authorizationCode;
    }

    public BearerAccessToken getAccessToken() {
        return accessToken;
    }

    public IDTokenClaimsSet getIdTokenClaimsSet() {
        try {
            if (idTokenClaimsSet != null) {
                return IDTokenClaimsSet.parse(idTokenClaimsSet.toJSONString());
            } else {
                return null;
            }
        } catch (ParseException e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    public void setIdTokenClaimsSet(IDTokenClaimsSet idTokenClaimsSet) {
        // IDTokenClaimsSet is not Serializable,
        if (idTokenClaimsSet != null) {
            this.idTokenClaimsSet = idTokenClaimsSet.toJSONObject();
        } else {
            this.idTokenClaimsSet = null;
        }
    }

    public Date getExpiresOn() {
        return expiresOn;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof OIDCStoreData)) {
            return false;
        }

        OIDCStoreData that = (OIDCStoreData) o;

        return Objects.equals(clientId, that.clientId);
    }

    @Override
    public final int hashCode() {
        return clientId != null ? clientId.hashCode() : 0;
    }
}
