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
package be.atbash.ee.security.octopus.authc;

import be.atbash.ee.security.octopus.token.AuthenticationToken;

/**
 * AuthenticationToken which can be used when insufficient/incorrect data was available on the requestHeader. Used in the OAuth2 and JWT authentication filters.
 */
public class IncorrectDataToken implements AuthenticationToken {

    private String message;

    public IncorrectDataToken(String message) {
        this.message = message;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return "IncorrectDataToken{" + "message='" + message + '\'' + '}';
    }
}
