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
package be.atbash.ee.security.octopus.authc;

import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.util.PublicAPI;

/**
 * Use this logout handler when we need to logout the subject from an external system, like Keycloak, in those scenarios
 * where we do not have a browser and thus can perform a redirect to the logout URL.
 * It is used for example by the Keycloak SE integration to log out the user in that case.
 * You can set the logic which needs to be performed by calling {@link AuthenticationInfoBuilder#withRemoteLogoutHandler(be.atbash.ee.security.octopus.authc.RemoteLogoutHandler) AuthenticationInfoBuilder.withRemoteLogoutHandler}.
 */
@PublicAPI
public interface RemoteLogoutHandler {
    /**
     * Callback triggered when a {@code Subject} logs-out of the system.
     * <p/>
     * This method will only be triggered when a Subject explicitly logs-out of the session.  It will not
     * be triggered if their Session times out.
     *
     * @param principals the identifying principals of the Subject logging out.
     */
    void onLogout(PrincipalCollection principals);
}
