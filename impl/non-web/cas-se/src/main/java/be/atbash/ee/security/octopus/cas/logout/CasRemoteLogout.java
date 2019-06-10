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
package be.atbash.ee.security.octopus.cas.logout;

import be.atbash.ee.security.octopus.authc.RemoteLogoutHandler;
import be.atbash.ee.security.octopus.cas.util.CasUtil;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import static be.atbash.ee.security.octopus.OctopusConstants.UPSTREAM_TOKEN;

public class CasRemoteLogout implements RemoteLogoutHandler {

    private Logger logger = LoggerFactory.getLogger(CasRemoteLogout.class);

    private CasUtil casUtil = new CasUtil();

    @Override
    public void onLogout(PrincipalCollection principals) {
        String ticket = principals.getPrimaryPrincipal().getUserInfo(UPSTREAM_TOKEN);

        URL casEndpoint = casUtil.getTicketEndpoint(ticket);

        try {
            HttpURLConnection connection = (HttpURLConnection) casEndpoint.openConnection();

            connection.setRequestMethod("DELETE");

            int status = connection.getResponseCode();
            if (status != 200) {
                logger.warn(String.format("DELETE to CAS ticket URL endpoint failed with status %s", status));
            } else {
                logger.debug(String.format("Logout performed for Service Ticket %s", ticket));
            }

        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

    }
}
