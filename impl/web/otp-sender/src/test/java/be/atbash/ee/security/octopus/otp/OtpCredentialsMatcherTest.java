package be.atbash.ee.security.octopus.otp;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.SimpleAuthenticationInfo;
import be.atbash.ee.security.octopus.authc.credential.CredentialsMatcher;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.OTPToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class OtpCredentialsMatcherTest {

    private CredentialsMatcher matcher = new OtpCredentialsMatcher();

    @Test
    public void doCredentialsMatch() {
        AuthenticationToken token = new OTPToken("123456");  // User value
        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        AuthenticationInfo info = new SimpleAuthenticationInfo(userPrincipal, "123456", true);
        boolean match = matcher.doCredentialsMatch(token, info);

        assertThat(match).isTrue();
    }

    @Test
    public void doCredentialsMatch_noMatch() {
        AuthenticationToken token = new OTPToken("123456");  // User value
        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        AuthenticationInfo info = new SimpleAuthenticationInfo(userPrincipal, "654321", true);
        boolean match = matcher.doCredentialsMatch(token, info);

        assertThat(match).isFalse();
    }

    @Test
    public void doCredentialsMatch_WrongToken() {
        AuthenticationToken token = new UsernamePasswordToken("Junit", "pass");
        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        AuthenticationInfo info = new SimpleAuthenticationInfo(userPrincipal, "654321", true);
        boolean match = matcher.doCredentialsMatch(token, info);

        assertThat(match).isFalse();
    }

}