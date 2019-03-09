package be.atbash.ee.security.octopus.otp.persistence;

import be.atbash.ee.security.octopus.otp.OTPUserData;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class DefaultOTPUserDataPersistenceTest {

    @Test
    public void retrieveData() {
        DefaultOTPUserDataPersistence otpUserDataPersistence = new DefaultOTPUserDataPersistence();

        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        OTPUserData userData = otpUserDataPersistence.retrieveData(userPrincipal);

        assertThat(userData).isNotNull();
        assertThat(userData.getKey()).hasSize(8);
        assertThat(userData.getValue()).isEqualTo(0);
    }

    @Test
    public void retrieveData_noCache() {
        DefaultOTPUserDataPersistence otpUserDataPersistence = new DefaultOTPUserDataPersistence();

        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        OTPUserData userData1 = otpUserDataPersistence.retrieveData(userPrincipal);
        OTPUserData userData2 = otpUserDataPersistence.retrieveData(userPrincipal);

        assertThat(userData1.getKey()).isNotEqualTo(userData2.getKey());

    }

}