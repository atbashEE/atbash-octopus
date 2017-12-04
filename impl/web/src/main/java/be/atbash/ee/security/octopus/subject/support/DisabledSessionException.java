/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.subject.support;


import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.session.SessionException;

/**
 * Exception thrown if attempting to create a new {@code Subject}
 * {@link org.apache.shiro.subject.Subject#getSession() session}, but that {@code Subject}'s sessions are disabled.
 * <p/>
 * Note that this exception represents an invalid API usage scenario - where Shiro has been configured to disable
 * sessions for a particular subject, but a developer is attempting to use that Subject's session.
 * <p/>
 * In other words, if this exception is encountered, it should be resolved by a configuration change for Shiro and
 * <em>not</em> by checking every Subject to see if they are enabled or not (which would likely introduce very
 * ugly/paranoid code checks everywhere a session is needed). This is why there is no
 * {@code subject.isSessionEnabled()} method.
 *
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.subject.support.DisabledSessionException"} )
public class DisabledSessionException extends SessionException {

    public DisabledSessionException(String message) {
        super(message);
    }
}
