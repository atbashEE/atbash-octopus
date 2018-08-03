/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.session.usage;

import be.atbash.util.CDIUtils;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

/**
 *
 */

public class OctopusSessionListener implements HttpSessionListener {
    @Override
    public void sessionCreated(HttpSessionEvent se) {
        CDIUtils.fireEvent(new SessionRegistryEvent(se.getSession(), UserAction.FIRST_ACCESS));
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {
        CDIUtils.fireEvent(new SessionRegistryEvent(se.getSession(), UserAction.SESSION_END));
    }

}
