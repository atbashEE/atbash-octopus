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

import jakarta.json.bind.serializer.DeserializationContext;
import jakarta.json.bind.serializer.JsonbDeserializer;
import jakarta.json.stream.JsonParser;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MPJWTTokenDeserializer implements JsonbDeserializer<MPJWTToken> {

    private static List<String> FIELD_NAMES = Arrays.asList("iss", "aud", "jti", "exp", "iat", "sub", "upn", "preferredUsername");
    private static List<String> COLLECTION_FIELD_NAMES = Arrays.asList("groups", "roles");

    @Override
    public MPJWTToken deserialize(JsonParser parser, DeserializationContext ctx, Type rtType) {
        MPJWTToken result = new MPJWTToken();
        while (parser.hasNext()) {
            JsonParser.Event event = parser.next();
            // This should be KEY_NAME
            if (JsonParser.Event.END_OBJECT == event) {
                break;
            }
            String fieldName = parser.getString();
            boolean handled= false;
            if (FIELD_NAMES.contains(fieldName)) {
                parser.next();  // To get the VALUE_STRING
                setFieldValue(result, fieldName, parser.getString());
                handled = true;
            }

            if (COLLECTION_FIELD_NAMES.contains(fieldName)) {
                setCollectionField(result, fieldName, parser);
                handled = true;
            }

            if (!handled) {
                parser.next();  // To get the VALUE_STRING
                result.addAdditionalClaims(fieldName, parser.getString());
            }

        }
        return result;
    }

    private void setCollectionField(MPJWTToken result, String fieldName, JsonParser parser) {
        List<String> data = new ArrayList<>();
        JsonParser.Event event = parser.next();
        while (event != JsonParser.Event.END_ARRAY) {
            if (event == JsonParser.Event.VALUE_STRING){
                data.add(parser.getString());
            }
            event = parser.next();
        }
        switch (fieldName) {
            case "groups":
                result.setGroups(data);
                break;
            case "roles":
                result.setRoles(data);
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + fieldName);
        }
    }

    private void setFieldValue(MPJWTToken result, String fieldName, String value) {
        switch (fieldName) {
            case "iss":
                result.setIss(value);
                break;
            case "aud":
                result.setAud(value);
                break;
            case "jti":
                result.setJti(value);
                break;
            case "exp":
                result.setExp(Long.parseLong(value) * 1000);
                break;
            case "iat":
                result.setIat(Long.parseLong(value) * 1000);
                break;
            case "sub":
                result.setSub(value);
                break;
            case "upn":
                result.setUpn(value);
                break;
            case "preferredUsername":
                result.setPreferredUsername(value);
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + fieldName);
        }
    }
}
