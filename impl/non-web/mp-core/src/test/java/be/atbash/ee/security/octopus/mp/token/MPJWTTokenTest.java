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
package be.atbash.ee.security.octopus.mp.token;

import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class MPJWTTokenTest {

    @Test
    public void toJSONString_additionalClaims() {

        MPJWTToken token = new MPJWTToken();

        token.setExp(new Date().getTime());
        token.setIat(new Date().getTime());

        Map<String, String> claims = new HashMap<>();
        claims.put("extra", "JUnit");
        claims.put("framework", "Octopus");
        token.setAdditionalClaims(claims);

        String json = token.toJSONString();

        assertThat(json).contains("\"framework\":\"Octopus\"");
        assertThat(json).contains("\"extra\":\"JUnit\"");

    }

    @Test
    public void decode() {

        JWTDecoder decoder = new JWTDecoder();

        MPJWTToken token = decoder.decode("{\"framework\":\"Octopus\",\"extra\":\"JUnit\",\"exp\":1514288343,\"iat\":1514288343}", MPJWTToken.class).getData();

        assertThat(token.getAdditionalClaims()).containsEntry("extra", "JUnit");
        assertThat(token.getAdditionalClaims()).containsEntry("framework", "Octopus");
    }

    @Test
    public void decode_withCollection() {

        JWTDecoder decoder = new JWTDecoder();

        MPJWTToken token = decoder.decode("{\"framework\":\"Octopus\",\"extra\":\"JUnit\",\"exp\":1514288343,\"iat\":1514288343,\"groups\":[\"value2\",\"value1\"]}", MPJWTToken.class).getData();

        assertThat(token.getAdditionalClaims()).containsEntry("extra", "JUnit");
        assertThat(token.getAdditionalClaims()).containsEntry("framework", "Octopus");

        assertThat(token.getGroups()).contains("value1","value2");
    }

}
