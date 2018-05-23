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
package be.atbash.ee.security.octopus.util.onlyduring;

import be.atbash.ee.security.octopus.context.ThreadContext;

import java.util.Arrays;
import java.util.List;

/**
 * Management around some special states where the special permissions are in effect.
 * {@link be.atbash.ee.security.octopus.authz.annotation.OnlyDuringAuthentication}
 * {@link be.atbash.ee.security.octopus.authz.annotation.OnlyDuringAuthenticationEvent}
 * {@link be.atbash.ee.security.octopus.authz.annotation.OnlyDuringAuthorization}
 * {@link be.atbash.ee.security.octopus.systemaccount.SystemAccount}
 */
public final class TemporaryAuthorizationContextManager {

    private static final String IN_AUTHENTICATION_FLAG = "InAuthentication";
    private static final String IN_AUTHORIZATION_FLAG = "InAuthorization";
    private static final String SYSTEM_ACCOUNT_AUTHENTICATION = "SystemAccountAuthentication";
    private static final String IN_AUTHENTICATION_EVENT_FLAG = "InAuthenticationEvent";

    private static final List<String> PRIVILEGED_CLASSES;

    static {
        PRIVILEGED_CLASSES = Arrays.asList("be.atbash.ee.security.octopus.realm.OctopusRealm"
                , "be.atbash.ee.security.octopus.realm.OctopusOfflineRealm", "be.atbash.ee.security.octopus.authc.DefaultWebAuthenticationListener");
    }

    private TemporaryAuthorizationContextManager() {
    }

    private static void checkPrivilegedCallerClass(Class<?> guard) {
        if (!PRIVILEGED_CLASSES.contains(getPrivilegedClassName(guard))) {
            throw new WrongExecutionContextException();
        }
    }

    private static String getPrivilegedClassName(Class<?> guard) {
        String result = null;
        if (guard != null && guard.getEnclosingMethod() != null) {
            result = guard.getEnclosingMethod().getDeclaringClass().getName();
        }
        return result;
    }

    /**
     * This is a internal method which required special privileges. When called from other methods, it will throw a @{code {@link WrongExecutionContextException}.
     *
     * @param guard Special guard class.
     */
    public static void startInAuthorization(Class<?> guard) {
        checkPrivilegedCallerClass(guard);
        ThreadContext.put(IN_AUTHORIZATION_FLAG, new InAuthorization());
    }

    /**
     * This is a internal method which required special privileges. When called from other methods, it will throw a @{code {@link WrongExecutionContextException}.
     *
     * @param guard Special guard class.
     */
    public static void startInAuthentication(Class<?> guard) {
        checkPrivilegedCallerClass(guard);
        ThreadContext.put(IN_AUTHENTICATION_FLAG, new InAuthentication());
    }

    /**
     * This is a internal method which required special privileges. When called from other methods, it will throw a @{code {@link WrongExecutionContextException}.
     *
     * @param guard Special guard class.
     */
    public static void startInAuthenticationEvent(Class<?> guard) {
        checkPrivilegedCallerClass(guard);
        ThreadContext.put(IN_AUTHENTICATION_EVENT_FLAG, new InAuthenticationEvent());
    }

    /**
     * This is a internal method which required special privileges. When called from other methods, it will throw a @{code {@link WrongExecutionContextException}.
     *
     * @param guard Special guard class.
     */
    // TODO is Special privileges required here or shiuld developer be start is from his own code?
    public static void startInSystemAccount(Class<?> guard) {
        checkPrivilegedCallerClass(guard);
        ThreadContext.put(SYSTEM_ACCOUNT_AUTHENTICATION, new InSystemAccountAuthentication());
    }

    public static boolean isInAuthorization() {
        return ThreadContext.get(IN_AUTHORIZATION_FLAG) instanceof InAuthorization;
    }

    public static boolean isInAuthentication() {
        return ThreadContext.get(IN_AUTHENTICATION_FLAG) instanceof InAuthentication;
    }

    public static boolean isInAuthenticationEvent() {
        return ThreadContext.get(IN_AUTHENTICATION_EVENT_FLAG) instanceof InAuthenticationEvent;
    }

    public static void stopInAuthorization() {
        ThreadContext.remove(IN_AUTHORIZATION_FLAG);
    }

    public static void stopInAuthentication() {

        ThreadContext.remove(IN_AUTHENTICATION_FLAG);
    }

    public static void stopInAuthenticationEvent() {
        ThreadContext.remove(IN_AUTHENTICATION_EVENT_FLAG);
    }

    public static void stopInSystemAccount() {
        ThreadContext.remove(SYSTEM_ACCOUNT_AUTHENTICATION);
    }

    // Marker classes which can only be created here
    private static final class InAuthentication {

        private InAuthentication() {
        }
    }

    private static final class InAuthorization {

        private InAuthorization() {
        }
    }

    private static final class InSystemAccountAuthentication {
        private InSystemAccountAuthentication() {
        }
    }

    private static class InAuthenticationEvent {

        private InAuthenticationEvent() {
        }
    }

}
