package be.atbash.ee.security.octopus.util;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


public class SecretUtilTest {

    @Test
    public void generateSecretBase64() {
        String secret = SecretUtil.getInstance().generateSecretBase64(16);
        assertThat(secret).hasSize(22);
    }
}