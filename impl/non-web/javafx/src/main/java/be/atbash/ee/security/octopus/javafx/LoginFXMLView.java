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
package be.atbash.ee.security.octopus.javafx;

import be.atbash.ee.security.octopus.authc.AuthenticationException;
import com.airhacks.afterburner.views.FXMLView;

import java.util.function.Consumer;

/**
 * Special FXMLView used for Login. It must respond on AuthenticationException given by the Octopus Core code.
 */

public abstract class LoginFXMLView extends FXMLView {

    /**
     * Returns the consumer for the AuthenticationException and updates the LoginView to indicate this situation to the end user.
     *
     * @return Method handling the AuthenticationException
     */
    public abstract Consumer<AuthenticationException> getAuthenticationExceptionCallback();

    /**
     * Should undo all actions performed in the Method handling the AuthenticationException.
     */
    public abstract void resetView();
}
