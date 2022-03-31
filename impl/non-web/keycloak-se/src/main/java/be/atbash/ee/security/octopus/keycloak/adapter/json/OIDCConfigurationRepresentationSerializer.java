package be.atbash.ee.security.octopus.keycloak.adapter.json;

import be.atbash.ee.security.octopus.json.AbstractJacksonJsonSerializer;
import jakarta.json.bind.serializer.JsonbSerializer;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;

public class OIDCConfigurationRepresentationSerializer extends AbstractJacksonJsonSerializer<OIDCConfigurationRepresentation> implements JsonbSerializer<OIDCConfigurationRepresentation> {


}
