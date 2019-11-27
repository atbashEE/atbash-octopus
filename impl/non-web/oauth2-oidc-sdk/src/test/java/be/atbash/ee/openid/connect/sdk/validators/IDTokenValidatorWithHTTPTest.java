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
package be.atbash.ee.openid.connect.sdk.validators;


import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.openid.connect.sdk.SubjectType;
import be.atbash.ee.openid.connect.sdk.op.OIDCProviderMetadata;
import be.atbash.ee.security.octopus.nimbus.jwk.JWK;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.After;
import org.junit.Before;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static net.jadler.Jadler.*;


/**
 * Tests the static factory method with HTTP retrieval of remote OP JWK set to
 * complete ID token validation.
 */
public class IDTokenValidatorWithHTTPTest {

    @Before
    public void setUp() {
        initJadler();
    }


    @After
    public void tearDown() {
        closeJadler();
    }


    private Map.Entry<OIDCProviderMetadata, List<RSAKey>> createOPMetadata()
            throws Exception {

        // Generate 2 RSA keys for the OP
        KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
        pairGen.initialize(2048);
        KeyPair keyPair = pairGen.generateKeyPair();

        RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID("1")
                .build();

        keyPair = pairGen.generateKeyPair();

        RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID("2")
                .build();

        OIDCProviderMetadata opMetadata = new OIDCProviderMetadata(
                new Issuer("http://localhost:" + port()),
                Collections.singletonList(SubjectType.PUBLIC),
                URI.create("http://localhost:" + port() + "/jwks.json"));

        opMetadata.setIDTokenJWSAlgs(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.HS256));
        opMetadata.setIDTokenJWEAlgs(Collections.singletonList(JWEAlgorithm.RSA1_5));
        opMetadata.setIDTokenJWEEncs(Arrays.asList(EncryptionMethod.A128CBC_HS256, EncryptionMethod.A128GCM));
        opMetadata.setTokenEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
        opMetadata.applyDefaults();

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/jwks.json")
                .respond()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(new JWKSet(Arrays.asList((JWK) rsaJWK1, (JWK) rsaJWK2)).toJSONObject().toString());

        return new AbstractMap.SimpleImmutableEntry<>(opMetadata, Arrays.asList(rsaJWK1, rsaJWK2));
    }


}
