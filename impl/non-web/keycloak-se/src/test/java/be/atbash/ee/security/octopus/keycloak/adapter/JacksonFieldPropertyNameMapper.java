package be.atbash.ee.security.octopus.keycloak.adapter;

import be.atbash.json.asm.Accessor;
import be.atbash.json.asm.mapper.FieldPropertyNameMapper;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 */

public class JacksonFieldPropertyNameMapper implements FieldPropertyNameMapper {

    @Override
    public String getPropertyName(Accessor accessor) {
        JsonProperty jsonProperty = accessor.getAnnotation(JsonProperty.class);
        if (jsonProperty != null) {
            return jsonProperty.value();
        }
        return null;
    }

    @Override
    public String getFieldName(Accessor accessor) {
        return null;
    }
}
