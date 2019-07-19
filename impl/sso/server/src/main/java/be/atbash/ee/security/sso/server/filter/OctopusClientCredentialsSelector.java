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
package be.atbash.ee.security.sso.server.filter;

import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.client.ClientInfoRetriever;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class OctopusClientCredentialsSelector implements ClientCredentialsSelector<Object> {

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @Override
    public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context<Object> context) throws InvalidClientException {
        ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(claimedClientID.getValue());
        if (clientInfo == null) {
            throw InvalidClientException.BAD_ID;
        }
        ArrayList<Secret> result = new ArrayList<Secret>();
        // For Octopus SSO, there the secret is a Base64 encoded array
        result.add(new Secret(new String(clientInfo.getClientSecretByte(), Charset.forName("UTF-8"))));
        // For Octopus as OAuth2 (like Google) provider replacement. There It is the plain text
        result.add(new Secret(clientInfo.getClientSecret()));  // TODO ? Is this correct
        return result;

    }

    @Override
    public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID, ClientAuthenticationMethod authMethod, JWSHeader jwsHeader, boolean forceRefresh, Context<Object> context) throws InvalidClientException {
        // TODO Support Public keys for JWT signing of ClientAuthentication
        return null;
    }


}
