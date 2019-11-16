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
package be.atbash.ee.security.octopus.sso.client;


import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.openid.connect.sdk.Nonce;

import java.io.Serializable;

/**
 *
 */
public class OpenIdVariableClientData implements Serializable {

    private State state;
    private Nonce nonce;
    private String rootURL;

    /**
     * Used from within the Octopus SE module.
     */
    public OpenIdVariableClientData() {
        this(null);
    }

    /**
     * Used from within the Octopus SSO client module.
     *
     * @param rootURL Root url of the client web application.
     */
    public OpenIdVariableClientData(String rootURL) {
        this.rootURL = rootURL;
        if (rootURL != null) {
            // Generate State
            state = new State();

            // Generate nonce
            nonce = new Nonce();
        }
    }

    public State getState() {
        return state;
    }

    public Nonce getNonce() {
        return nonce;
    }

    public String getRootURL() {
        return rootURL;
    }
}
