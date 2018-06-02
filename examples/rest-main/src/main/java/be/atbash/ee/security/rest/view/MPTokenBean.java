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
package be.atbash.ee.security.rest.view;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.mp.token.MPJWTToken;
import be.atbash.ee.security.octopus.mp.token.MPJWTTokenBuilder;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static be.atbash.ee.security.octopus.WebConstants.AUTHORIZATION_HEADER;
import static be.atbash.ee.security.octopus.WebConstants.BEARER;

/**
 *
 */
@RequestScoped
@Named("mpTokenBean")
public class MPTokenBean {

    @Inject
    private MPJWTTokenBuilder tokenBuilder;

    @Inject
    private JWTEncoder jwtEncoder;

    @Inject
    private KeySelector keySelector;

    public void testMPToken() {

        MPJWTToken mpjwtToken = tokenBuilder.setAudience("Octopus Rest MP").
                setSubject("Octopus Test").build();

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(keySelector.selectAtbashKey(criteria))
                .build();
        String bearerHeader = jwtEncoder.encode(mpjwtToken, parameters);

        Client client = ClientBuilder.newClient();
        WebTarget target = client.target("http://localhost:8080/rest-mp/data/hello");
        Response response = target.request(MediaType.APPLICATION_JSON)
                .header(AUTHORIZATION_HEADER, BEARER + " " + bearerHeader)
                .get();
        System.out.println("status : " + response.getStatus());
        System.out.println(response.readEntity(String.class));

    }
}
