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
package be.atbash.ee.security.octopus.keycloak.adapter;

import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OIDCAuthenticationError;
import org.keycloak.adapters.authentication.ClientCredentialsProviderUtils;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * TODO Use the refresh token to get a new set of tokens.
 * http://connect2id.com/learn/openid-connect
 */
public class KeycloakAuthenticator {

    private KeycloakDeployment deployment;

    public KeycloakAuthenticator(KeycloakDeployment deployment) {
        this.deployment = deployment;
    }

    public KeycloakUserToken authenticate(UsernamePasswordToken token) {
        AccessTokenResponse accessToken = getAccessToken(token);

        return AccessTokenHandler.extractUser(deployment, accessToken);
    }

    // TODO This uses the Refresh Token? is this correct. How used in Octopus?
    public void validate(String token) {
        try {
            List<NameValuePair> formParams = new ArrayList<>();

            formParams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, "refresh_token"));
            formParams.add(new BasicNameValuePair(OAuth2Constants.REFRESH_TOKEN, token));
            //formParams.add(new BasicNameValuePair(OAuth2Constants.REDIRECT_URI, "http://localhost"));

            HttpPost post = new HttpPost(deployment.getTokenUrl());
            ClientCredentialsProviderUtils.setClientCredentials(deployment, post, formParams);

            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formParams, "UTF-8");
            post.setEntity(form);
            HttpResponse response = deployment.getClient().execute(post);
            int status = response.getStatusLine().getStatusCode();

            if (status != 200) {
                throw new OIDCAuthenticationException(OIDCAuthenticationError.Reason.INVALID_TOKEN);
            }
            // TODO Refresh the tokens
        } catch (IOException e) {
            throw new OIDCAuthenticationException(OIDCAuthenticationError.Reason.OAUTH_ERROR);
        }
    }

    private AccessTokenResponse getAccessToken(UsernamePasswordToken token) {
        AccessTokenResponse tokenResponse;
        HttpClient client = deployment.getClient();

        HttpPost post = new HttpPost(
                KeycloakUriBuilder.fromUri(deployment.getAuthServerBaseUrl())
                        .path(ServiceUrlConstants.TOKEN_PATH).build(deployment.getRealm()));
        List<NameValuePair> formparams = new ArrayList<>();
        formparams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD));
        formparams.add(new BasicNameValuePair("username", token.getUsername()));
        formparams.add(new BasicNameValuePair("password", String.valueOf(token.getPassword())));

        ClientCredentialsProviderUtils.setClientCredentials(deployment, post, formparams);

        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);

            HttpResponse response = client.execute(post);
            int status = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (status != 200) {
                String errMessage = EntityUtils.toString(entity, "UTF-8");
                // TODO This is JSON, should we extract the property 'error_description' ??
                throw new KeycloakRemoteConnectionException(String.format("Bad status: %s, message '%s'", status, errMessage));
            }
            if (entity == null) {
                throw new KeycloakRemoteConnectionException("No Entity");
            }
            try (InputStream is = entity.getContent()) {
                tokenResponse = JsonSerialization.readValue(is, AccessTokenResponse.class);
            }
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

        return tokenResponse;
    }

}
