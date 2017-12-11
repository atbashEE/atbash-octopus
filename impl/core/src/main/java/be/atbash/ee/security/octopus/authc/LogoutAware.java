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
package be.atbash.ee.security.octopus.authc;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;

/**
 * An SPI interface allowing cleanup logic to be executed during logout of a previously authenticated Subject/user.
 * <p>
 * <p>As it is an SPI interface, it is really intended for SPI implementors such as those implementing Realms.
 * <p>
 * <p>All of Shiro's concrete Realm implementations implement this interface as a convenience for those wishing
 * to subclass them.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authc.LogoutAware"})
// FIXME Integrate in classes
public interface LogoutAware {

    /**
     * Callback triggered when a <code>Subject</code> logs out of the system.
     *
     * @param principals the identifying principals of the Subject logging out.
     */
    void onLogout(PrincipalCollection principals);
}
