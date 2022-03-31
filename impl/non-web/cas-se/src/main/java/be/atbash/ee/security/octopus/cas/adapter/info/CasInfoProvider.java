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
package be.atbash.ee.security.octopus.cas.adapter.info;

import be.atbash.ee.security.octopus.cas.adapter.CasUserToken;
import be.atbash.ee.security.octopus.cas.config.OctopusCasConfiguration;
import be.atbash.ee.security.octopus.cas.exception.CasAuthenticationException;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class CasInfoProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(CasInfoProvider.class);

    @Inject
    private OctopusCasConfiguration casConfiguration;

    private TicketValidator ticketValidator;

    public CasInfoProvider() {
        init();
    }

    @PostConstruct
    public void init() {
        if (ticketValidator == null ) {
            if (casConfiguration == null) {
                casConfiguration = OctopusCasConfiguration.getInstance();
            }

            String urlPrefix = casConfiguration.getSSOServer();

            switch (casConfiguration.getCASProtocol()) {

                case CAS:
                    ticketValidator = new Cas30ServiceTicketValidator(urlPrefix);
                    break;

                case SAML:
                    ticketValidator = new Saml11TicketValidator(urlPrefix);
                    break;
            }
        }
    }

    public CasUserToken retrieveUserInfo(String ticket) {
        CasUserToken result = new CasUserToken(ticket);

        try {
            // contact CAS server to validate service ticket
            Assertion casAssertion = ticketValidator.validate(ticket, casConfiguration.getCASService());
            // get principal, user id and attributes
            AttributePrincipal casPrincipal = casAssertion.getPrincipal();
            String userId = casPrincipal.getName();

            result.setUserName(userId);

            Map<String, Object> attributes = casPrincipal.getAttributes();

            result.setEmail((String) attributes.get(casConfiguration.getCASEmailProperty()));

            Map<String, Serializable> info = new HashMap<>();
            for (Map.Entry<String, Object> entry : attributes.entrySet()) {
                if (entry.getValue() instanceof Serializable) {
                    info.put(entry.getKey(), (Serializable) entry.getValue());
                }
            }

            result.setUserInfo(info);

        } catch (TicketValidationException e) {
            LOGGER.error("Validating CAS Ticket failed", e);
            throw new CasAuthenticationException(e);
        }
        return result;
    }

    // Java SE Support
    private static CasInfoProvider INSTANCE;

    private static final Object LOCK = new Object();

    public static CasInfoProvider getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new CasInfoProvider();
                    INSTANCE.init();
                }
            }
        }
        return INSTANCE;
    }

}
