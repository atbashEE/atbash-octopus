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
package be.atbash.ee.security.octopus.mp.token.json;

import be.atbash.ee.security.octopus.mp.token.MPJWTToken;

import jakarta.json.bind.serializer.JsonbSerializer;
import jakarta.json.bind.serializer.SerializationContext;
import jakarta.json.stream.JsonGenerator;
import java.util.Map;

public class MPJWTTokenSerializer implements JsonbSerializer<MPJWTToken> {
    @Override
    public void serialize(MPJWTToken token, JsonGenerator generator, SerializationContext ctx) {


        generator.writeStartObject();

        if (token.getIss() != null) {
            generator.write("iss", token.getIss());
        }

        if (token.getAud() != null) {
            generator.write("aud", token.getAud());
        }
        if (token.getJti() != null) {
            generator.write("jti", token.getJti());
        }
        if (token.getExp() != null) {
            generator.write("exp", token.getExp());
        }
        if (token.getIat() != null) {
            generator.write("iat", token.getIat());
        }

        if (token.getSub() != null) {
            generator.write("sub", token.getSub());
        }
        if (token.getUpn() != null) {
            generator.write("upn", token.getUpn());
        }
        if (token.getPreferredUsername() != null) {
            generator.write("preferred_username", token.getPreferredUsername());
        }


        // FIXME The other properties

        if (token.getAdditionalClaims() != null) {
            for (Map.Entry<String, String> entry : token.getAdditionalClaims().entrySet()) {
                generator.write(entry.getKey(), entry.getValue());
            }
        }

        generator.writeStartArray("groups");

        for (String group : token.getGroups()) {
            generator.write(group);
        }
        generator.writeEnd();  // End of Groups array

        generator.writeEnd();  // End of Object

    }
}
