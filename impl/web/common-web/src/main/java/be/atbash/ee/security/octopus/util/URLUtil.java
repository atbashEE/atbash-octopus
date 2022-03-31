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
package be.atbash.ee.security.octopus.util;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;

/**
 *
 *
 */
@ApplicationScoped
public class URLUtil {

    public String determineRoot(HttpServletRequest req) {
        return req.getScheme() + "://" +
                req.getServerName() +
                getServerPort(req) +
                req.getContextPath();
    }

    private String getServerPort(HttpServletRequest req) {
        String result = ':' + String.valueOf(req.getServerPort());
        if (":80".equals(result)) {
            result = "";
        }
        if (":443".equals(result)) {
            result = "";
        }
        return result;
    }

    /**
     * baseURI is the contextRoot appended with the ApplicationPath
     * TODO Document that when creating a Octopus SSO Server application Path can only be a 1 'level' (like /data, but not /octopus/data)
     *
     * @param baseURI
     * @return
     */
    // FIXME This one us used on Octopus SSO Server. Required that it keep defaultPorts? (removed by determineRoot using ServletRequest)
    public String determineRoot(URI baseURI) {
        String base = baseURI.toASCIIString();

        // Strip the trailing /
        String result = base.substring(0, base.length() - 1);

        // Find the last /
        int idx = result.lastIndexOf('/');

        return result.substring(0, idx);
    }

}
