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
package be.atbash.ee.security.sso.server.token;

import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.security.octopus.token.SystemAuthenticationToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;

/**
 *
 */

public class OIDCEndpointToken implements ValidatedAuthenticationToken, SystemAuthenticationToken {

    private ClientID clientId;

    public OIDCEndpointToken(ClientID clientId) {
        this.clientId = clientId;
    }

    public ClientID getClientId() {
        return clientId;
    }

    @Override
    public Object getPrincipal() {
        return getClientId();
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
