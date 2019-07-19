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

import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;

import java.util.List;

/**
 *
 */
public interface SSOTokenStore {

    UserPrincipal getUserByAccessCode(String accessCode);

    OIDCStoreData getOIDCDataByAccessToken(String accessCode);

    OIDCStoreData getOIDCDataByAuthorizationCode(AuthorizationCode authorizationCode, ClientID clientId);

    TokenStoreInfo getUserByCookieToken(String cookieToken);

    void removeUser(UserPrincipal userPrincipal);

    void addLoginFromClient(UserPrincipal userPrincipal, String cookieToken, String userAgent, String remoteHost, OIDCStoreData oidcStoreData);

    List<OIDCStoreData> getLoggedInClients(UserPrincipal userPrincipal);
}
