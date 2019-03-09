package be.atbash.ee.security.octopus.otp;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.otp.persistence.DefaultOTPUserDataPersistence;
import be.atbash.ee.security.octopus.otp.persistence.OTPUserDataPersistence;
import be.atbash.ee.security.octopus.otp.provider.HOTPProvider;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.OTPToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.util.TestReflectionUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class OTPTwoStepProviderTest {

    @Mock
    private OTPProviderFactory otpProviderFactoryMock;

    @Mock
    private OTPValueSender otpValueSenderMock;

    @Mock
    private WebSubject webSubjectMock;

    private OTPUserDataPersistence otpUserDataPersistence;

    @InjectMocks
    private OTPTwoStepProvider twoStepProvider;

    @Test
    public void startSecondStep() throws IllegalAccessException, NoSuchFieldException {
        OTPProvider provider = new HOTPProvider();
        provider.setProperties(6, new Properties());
        when(otpProviderFactoryMock.retrieveOTPProvider()).thenReturn(provider);

        otpUserDataPersistence = new DefaultOTPUserDataPersistence();
        TestReflectionUtils.injectDependencies(twoStepProvider, otpUserDataPersistence);

        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        twoStepProvider.startSecondStep(null, userPrincipal);

        verify(otpValueSenderMock).sendValue(any(UserPrincipal.class), anyString());
        Map<Serializable, String> otpValues = TestReflectionUtils.getValueOf(twoStepProvider, "otpValues");
        assertThat(otpValues).hasSize(1);
        assertThat(otpValues).containsKey(userPrincipal.getId());
    }

    @Test
    public void getAuthenticationInfo() throws NoSuchFieldException {
        Map<Serializable, String> otpValues = new HashMap<>();
        otpValues.put(1L, "654321");
        TestReflectionUtils.setFieldValue(twoStepProvider, "otpValues", otpValues);

        ThreadContext.bind(webSubjectMock);
        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        when(webSubjectMock.getPrincipal()).thenReturn(userPrincipal);

        AuthenticationToken token = new OTPToken("123456");
        AuthenticationInfo info = twoStepProvider.getAuthenticationInfo(token);

        assertThat(info).isNotNull();
        assertThat(info.getPrincipals()).containsOnly(userPrincipal);
        assertThat(info.isOneTimeAuthentication()).isTrue();
        assertThat(info.getCredentials()).isEqualTo("654321");

        assertThat(otpValues).isEmpty();  // We have removed the stored value
    }

    @Test
    public void getAuthenticationInfo_wrongToken() throws NoSuchFieldException {
        Map<Serializable, String> otpValues = new HashMap<>();
        otpValues.put(1L, "654321");
        TestReflectionUtils.setFieldValue(twoStepProvider, "otpValues", otpValues);

        AuthenticationToken token = new UsernamePasswordToken("JUnit", "Test");
        AuthenticationInfo info = twoStepProvider.getAuthenticationInfo(token);

        assertThat(info).isNull();

        assertThat(otpValues).isNotEmpty();  // We have NOT removed the stored value
    }

}