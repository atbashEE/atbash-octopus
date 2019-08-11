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
package be.atbash.ee.security.octopus.sso.client.debug;

import be.atbash.ee.security.octopus.OctopusConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import java.io.IOException;
import java.net.URI;


/**
 *
 */
public class DebugClientRequestFilter implements ClientRequestFilter {

    private Logger logger = LoggerFactory.getLogger(DebugClientRequestFilter.class);

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {

        URI uri = requestContext.getUri();
        String authorization = requestContext.getHeaderString(OctopusConstants.AUTHORIZATION_HEADER);
        Object entity = requestContext.getEntity();

        int correlationId = CorrelationCounter.VALUE.getAndIncrement();

        if (authorization != null) {
            if (entity != null) {
                logger.info(String.format("(correlationId %5d) Sending to %s with Authorization header '%s' and entity '%s'", correlationId, uri.toString(), authorization, entity));
            } else {
                logger.info(String.format("(correlationId %5d) Sending to %s with Authorization header '%s'", correlationId, uri.toString(), authorization));

            }
        } else {
            if (entity != null) {
                logger.info(String.format("(correlationId %5d) Sending to %s with entity '%s'", correlationId, uri.toString(), entity));
            } else {
                logger.info(String.format("(correlationId %5d) Sending to %s", correlationId, uri.toString()));

            }

        }

        requestContext.setProperty(CorrelationCounter.class.getName(), correlationId);
    }
}
