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
