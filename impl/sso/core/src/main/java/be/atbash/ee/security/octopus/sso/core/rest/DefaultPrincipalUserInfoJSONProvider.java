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
package be.atbash.ee.security.octopus.sso.core.rest;

import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.sso.core.rest.reflect.Bean;
import be.atbash.ee.security.octopus.sso.core.rest.reflect.Property;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.enterprise.inject.Vetoed;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonValue;
import java.text.ParseException;
import java.util.Map;

/**
 * TODO, this doesn't support serialization of values in super classes.
 * TODO On Java EE 8, use JSON-B for this.
 */
@Vetoed
public class DefaultPrincipalUserInfoJSONProvider implements PrincipalUserInfoJSONProvider {

    private static Logger LOGGER = LoggerFactory.getLogger(DefaultPrincipalUserInfoJSONProvider.class);

    @Override
    public String writeValue(Object data) {
        JsonObjectBuilder result = Json.createObjectBuilder();

        Bean<?> bean = Bean.forClass(data.getClass());
        Property[] declaredProperties = bean.getDeclaredProperties();
        String name;
        Object value;
        for (Property declaredProperty : declaredProperties) {
            name = declaredProperty.getName();
            value = bean.getProperty(name).get(data);
            if (Property.isBasicPropertyType(value)) {
                JSONObjectUtils.addValue(result, name, value);
            } else if (value.getClass().isEnum()) {
                result.add(name, value.toString());
            } else {
                // FIXME Is this still correct with JSONP
                result.add(name, Json.createValue(writeValue(value)));  // Recursive call
            }
        }
        return result.build().toString();
    }

    @Override
    public <T> T readValue(String json, Class<T> classType) {
        Bean<T> bean = Bean.forClass(classType);
        T result;
        try {
            result = classType.newInstance();

            JsonObject jsonObject = JSONObjectUtils.parse(json);

            Object value;
            for (Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {

                value = JSONObjectUtils.getJsonValueAsObject(entry.getValue());

                Property property = bean.getProperty(entry.getKey());
                if (property.isWritable()) {
                    setPropertyValue(result, value, property);
                }
            }
        } catch (InstantiationException | ParseException | IllegalAccessException e) {
            LOGGER.warn(e.getMessage());
            throw new AtbashUnexpectedException(e.getMessage());
        }
        return result;
    }

    private <T> void setPropertyValue(T result, Object value, Property property) {
        Class<?> actualType = property.getActualType();
        if (Property.isBasicPropertyType(actualType)) {
            if (actualType.equals(Long.class) && value instanceof Integer) {
                Integer intValue = (Integer) value;
                property.set(result, intValue.longValue());
            } else {
                property.set(result, value);
            }
        } else if (actualType.isEnum()) {
            for (Object o : actualType.getEnumConstants()) {
                if (o.toString().equals(value)) {
                    property.set(result, o);
                }
            }
        } else {
            property.set(result, readValue(value.toString(), actualType));
        }
    }
}
