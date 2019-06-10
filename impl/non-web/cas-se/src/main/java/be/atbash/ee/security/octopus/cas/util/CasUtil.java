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
package be.atbash.ee.security.octopus.cas.util;

import be.atbash.ee.security.octopus.cas.config.OctopusCasConfiguration;
import be.atbash.util.exception.AtbashUnexpectedException;

import java.net.MalformedURLException;
import java.net.URL;

public class CasUtil {

    public static final String V1_TICKETS = "/v1/tickets";

    private OctopusCasConfiguration configuration;

    public CasUtil() {
        configuration = OctopusCasConfiguration.getInstance();
    }

    public URL getTicketEndpoint() {
        try {
            return new URL(configuration.getSSOServer() + V1_TICKETS);
        } catch (MalformedURLException e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    public URL getTicketEndpoint(String ticket) {
        try {
            return new URL(configuration.getSSOServer() + V1_TICKETS + "/" + ticket);
        } catch (MalformedURLException e) {
            throw new AtbashUnexpectedException(e);
        }
    }
}
