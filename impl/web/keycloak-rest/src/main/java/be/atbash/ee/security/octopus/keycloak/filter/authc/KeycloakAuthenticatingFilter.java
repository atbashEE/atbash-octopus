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
package be.atbash.ee.security.octopus.keycloak.filter.authc;

import be.atbash.ee.security.octopus.authc.CredentialsException;
import be.atbash.ee.security.octopus.filter.RestAuthenticatingFilter;
import be.atbash.ee.security.octopus.keycloak.adapter.AccessTokenHandler;
import be.atbash.ee.security.octopus.keycloak.adapter.KeycloakDeploymentHelper;
import be.atbash.ee.security.octopus.keycloak.adapter.KeycloakUserToken;
import be.atbash.ee.security.octopus.keycloak.config.OctopusKeycloakConfiguration;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.util.JsonSerialization;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

import static be.atbash.ee.security.octopus.WebConstants.AUTHORIZATION_HEADER;
import static be.atbash.ee.security.octopus.WebConstants.BEARER;

/**
 *
 */
@ApplicationScoped
public class KeycloakAuthenticatingFilter extends RestAuthenticatingFilter {

    @Inject
    private OctopusKeycloakConfiguration keycloakConfiguration;

    private KeycloakDeployment deployment;

    @PostConstruct
    public void initInstance() {
        setName("authcKeycloak");
        deployment = KeycloakDeploymentHelper.loadDeploymentDescriptor(keycloakConfiguration.getLocationKeycloakFile());
    }

    @Override
    protected AuthenticationToken createToken(String token) {

        String url = deployment.getAccountUrl().replace("account", "protocol/openid-connect/userinfo");
        // localhost:8080/auth/realms/demo/protocol/openid-connect/userinfo

        HttpGet get = new HttpGet(url);

        // add request header
        get.addHeader(AUTHORIZATION_HEADER, BEARER + " " + token);
        get.addHeader("Accept", "application/json");

        KeycloakUserToken result;

        try {
            HttpResponse userInfoResponse = deployment.getClient().execute(get);
            if (userInfoResponse.getStatusLine().getStatusCode() == 200) {
                String id = EntityUtils.toString(userInfoResponse.getEntity());

                IDToken idToken = JsonSerialization.readValue(id, IDToken.class);

                // Get AccessToken. We don't need to verify the JWT (since it is used in the call to UserInfo endpoint
                // and thus already verified by Keycloak.
                AccessToken accessToken;
                try {
                    JWSInput jwsInput = new JWSInput(token);
                    accessToken = jwsInput.readJsonContent(AccessToken.class);
                } catch (JWSInputException e) {
                    throw new AtbashUnexpectedException(e);
                }

                result = AccessTokenHandler.extractUser(accessToken, idToken, token);

            } else {
                throw new CredentialsException(userInfoResponse.getStatusLine().getReasonPhrase());
            }
        } catch (IOException e) {
            throw new CredentialsException(e.getMessage());
        }

        return result;

    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return executeLogin(request, response);
    }
}
