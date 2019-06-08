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
package be.atbash.ee.security.octopus.cas.adapter;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.authc.AuthenticationStrategy;
import be.atbash.ee.security.octopus.cas.adapter.info.CasInfoProvider;
import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class ClientAuthenticationInfoProvider extends AuthenticationInfoProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientAuthenticationInfoProvider.class);

    private TicketRequestor requestor;
    private CasInfoProvider infoProvider;

    @PostConstruct
    public void init() {
        if (requestor == null) {
            requestor = new TicketRequestor();
            infoProvider = CasInfoProvider.getInstance();
        }
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        init();
        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        if (token instanceof UsernamePasswordToken) {
            // for the Java SE use case

            String grantingTicket = requestor.getGrantingTicket((UsernamePasswordToken) token);
            String serviceTicket = requestor.getServiceTicket(grantingTicket);

            CasUserToken casUserToken = infoProvider.retrieveUserInfo(serviceTicket);

            builder.principalId(casUserToken.getUserName()).userName(casUserToken.getUserName());

            builder.name(casUserToken.getName());
            builder.addUserInfo(casUserToken.getUserInfo());
            builder.token(casUserToken);

            // In order for the logout with CAS.
            //builder.withRemoteLogoutHandler(new KeycloakRemoteLogout());
            // FIXME

            return builder.build();
        }
        /*
        FIXME
        if (token instanceof CasUserToken) {
            // For the Web use case
            CasUserToken userToken = (CasUserToken) token;

            builder.principalId(userToken.getId());

            builder.name(userToken.getName());
            //builder.addUserInfo(OctopusConstants.EXTERNAL_SESSION_ID, keycloakUserToken.getClientSession());
            builder.token(userToken);

            return builder.build();

        }

         */
        return null;
    }

    @Override
    public AuthenticationStrategy getAuthenticationStrategy() {
        return AuthenticationStrategy.SUFFICIENT;
    }
}
