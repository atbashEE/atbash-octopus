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
package be.atbash.ee.security.octopus.authz.violation;

import be.atbash.util.PublicAPI;

/**
 * TODO When it is just a BasicVaiolation?
 */
@PublicAPI
public class BasicAuthorizationViolation implements AuthorizationViolation {

    private String reason;
    private String exceptionPoint;

    public BasicAuthorizationViolation(String reason, String exceptionPoint) {
        this.reason = reason;
        this.exceptionPoint = exceptionPoint;
    }

    @Override
    public String getExceptionPoint() {
        return exceptionPoint;
    }

    @Override
    public String getReason() {
        return reason;
    }

    @Override
    public String toString() {
        return getReason() + '@' + exceptionPoint;
    }
}
