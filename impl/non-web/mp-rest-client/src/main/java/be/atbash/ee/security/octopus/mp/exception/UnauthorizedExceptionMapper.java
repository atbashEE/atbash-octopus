/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.mp.exception;

import be.atbash.ee.security.octopus.authz.UnauthorizedException;
import org.eclipse.microprofile.rest.client.ext.ResponseExceptionMapper;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

/**
 * FIXME, this needs to be in some general artifact. Can also be used for KeyCloak rest client for ex.
 */

public class UnauthorizedExceptionMapper implements ResponseExceptionMapper<UnauthorizedException> {

    @Override
    public UnauthorizedException toThrowable(Response response) {
        ErrorInfo errorInfo = response.readEntity(ErrorInfo.class);
        return new UnauthorizedException(errorInfo.getMessage());
    }

    @Override
    public int getPriority() {
        return 1;
    }

    @Override
    public boolean handles(int status, MultivaluedMap multivaluedMap) {
        return status == 401;
    }
}
