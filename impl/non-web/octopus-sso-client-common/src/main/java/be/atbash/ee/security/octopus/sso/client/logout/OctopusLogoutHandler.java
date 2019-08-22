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
package be.atbash.ee.security.octopus.sso.client.logout;

import be.atbash.ee.security.octopus.authc.RemoteLogoutHandler;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Logout from the SSO Server
 */
public class OctopusLogoutHandler implements RemoteLogoutHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(OctopusLogoutHandler.class);

    @Override
    public void onLogout(PrincipalCollection principals) {

        OctopusSSOToken octopusSSOToken = principals.oneByType(OctopusSSOToken.class);
        // TODO Verify if we should use BackChannelLogoutRequest
        String url = LogoutURLCreator.getInstance().createLogoutURL(null, octopusSSOToken.getAccessToken());

        try {
            URL obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();

            con.setRequestMethod("GET");

            int responseCode = con.getResponseCode();
            if (responseCode < 200 || responseCode > 299) {
                LOGGER.warn(String.format("Received invalid status on the logout URL of Octopus SSO Server : %s", responseCode));
            }
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }


    }
}
