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
package be.atbash.ee.security.octopus.audit;

import be.atbash.util.PublicAPI;

/**
 *
 */
@PublicAPI
public class OctopusAuditEvent {

    private String requestURI;
    private Object principal;
    private String remoteAddress;
    private String userAgent;

    public OctopusAuditEvent(String requestURI, Object principal, String remoteAddress, String userAgent) {
        this.requestURI = requestURI;
        this.principal = principal;
        this.remoteAddress = remoteAddress;
        this.userAgent = userAgent;
    }

    public String getRequestURI() {
        return requestURI;
    }

    public Object getPrincipal() {
        return principal;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }
}
