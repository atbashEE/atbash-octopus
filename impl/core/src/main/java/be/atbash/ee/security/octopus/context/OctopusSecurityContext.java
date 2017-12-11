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
package be.atbash.ee.security.octopus.context;

import be.atbash.ee.security.octopus.PublicAPI;
import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.token.AuthenticationToken;

import java.io.Serializable;

/**
 *
 */
@PublicAPI
public class OctopusSecurityContext implements Serializable {

    private static final OctopusSecurityContext INSTANCE = new OctopusSecurityContext();

    OctopusSecurityContext() {
    }

    public void authenticate(AuthenticationToken authenticationToken) {
        SecurityUtils.getSubject().login(authenticationToken);
    }

    public static OctopusSecurityContext getInstance() {
        return INSTANCE;
    }
}
