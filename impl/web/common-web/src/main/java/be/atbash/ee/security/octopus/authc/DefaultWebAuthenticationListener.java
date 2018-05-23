/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.authc;

import be.atbash.ee.security.octopus.authc.event.LogonEvent;
import be.atbash.ee.security.octopus.authc.event.LogonFailureEvent;
import be.atbash.ee.security.octopus.authc.event.LogoutEvent;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.systemaccount.SystemAccountAuthenticationToken;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.onlyduring.TemporaryAuthorizationContextManager;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Event;
import javax.inject.Inject;

@ApplicationScoped
public class DefaultWebAuthenticationListener implements AuthenticationListener {

    @Inject
    private Event<LogonEvent> logonEvent;

    @Inject
    private Event<LogonFailureEvent> logonFailureEvent;

    @Inject
    private Event<LogoutEvent> logoutEvent;

    @Override
    public void onSuccess(AuthenticationToken token, AuthenticationInfo info) {
        // FIXME ProcessAuthenticationToken -> marker interface for toeksn used in process to Process like OIDC retrieval of Tokens
        //if (!(token instanceof ProcessAuthenticationToken) && !(token instanceof SystemAccountAuthenticationToken)) {
        if (!(token instanceof SystemAccountAuthenticationToken)) {
            LogonEvent event = new LogonEvent(token, info);

            class Guard {
            }
            TemporaryAuthorizationContextManager.startInAuthenticationEvent(Guard.class);
            try {
                logonEvent.fire(event);
            } finally {
                // In any case (also in case of access denied) we need to remove this flag
                TemporaryAuthorizationContextManager.stopInAuthenticationEvent();
            }
        }
    }

    @Override
    public void onFailure(AuthenticationToken token, AuthenticationException ae) {
        // FIXME ProcessAuthenticationToken
        //if (!(token instanceof ProcessAuthenticationToken)) {
        LogonFailureEvent event = new LogonFailureEvent(token, ae);
        logonFailureEvent.fire(event);
        //}
    }

    @Override
    public void onLogout(PrincipalCollection principals) {
        if (principals.getPrimaryPrincipal() instanceof UserPrincipal) {
            LogoutEvent event = new LogoutEvent((UserPrincipal) principals.getPrimaryPrincipal());
            logoutEvent.fire(event);
        }
    }

}
