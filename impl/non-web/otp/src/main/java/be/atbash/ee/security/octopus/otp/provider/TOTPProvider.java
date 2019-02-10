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
package be.atbash.ee.security.octopus.otp.provider;


import be.atbash.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.otp.OTPProvider;
import be.atbash.ee.security.octopus.otp.OTPUserData;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * http://blog.geuer-pollmann.de/blog/2014/12/15/generating-qr-codes-in-html/
 * http://thegreyblog.blogspot.be/2011/12/google-authenticator-using-it-in-your.html
 * https://github.com/adsllc/PHPOTP/blob/master/PHPOTP.php
 * https://github.com/njl07/otp.js
 */
public class TOTPProvider implements OTPProvider {

    private static final String ALGORITHM = "algorithm";

    private Properties properties;
    private int digits;

    @Override
    public String generate(OTPUserData data) {
        long l = new Date().getTime() / TimeUnit.SECONDS.toMillis(30);

        return generateForValue(data.getKey(), l);

    }

    private String generateForValue(byte[] key, long l) {
        String alg = null;

        if (properties.containsKey(ALGORITHM)) {
            alg = properties.get(ALGORITHM).toString();
        }

        if (alg == null) {
            throw new ConfigurationException("TOTPProvider is missing the configuration for " + ALGORITHM);
        }

        return generateTOTP(key, l, digits, alg);
    }

    @Override
    public void setProperties(int digits, Properties properties) {
        this.digits = digits;
        this.properties = properties;
    }

    @Override
    public boolean supportValidate() {
        return true;
    }

    @Override
    public boolean valid(OTPUserData data, int window, String userOTP) {
        long l = new Date().getTime() / TimeUnit.SECONDS.toMillis(30);
        boolean result = false;
        for (int i = -window; i < 1; i++) {
            String code = generateForValue(data.getKey(), l + i);
            if (code.equals(userOTP)) {
                result = true;
            }
            if (result) {
                break;
            }
        }
        return result;
    }

    /**
     * This method uses the JCE to provide the crypto algorithm. HMAC computes a
     * Hashed Message Authentication Code with the crypto hash algorithm as a
     * parameter.
     *
     * @param crypto   : the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
     * @param keyBytes : the bytes to use for the HMAC key
     * @param text     : the message or text to be authenticated
     */
    private byte[] hmacSha(String crypto, byte[] keyBytes, byte[] text) {
        try {
            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }

    /**
     * This method generates a TOTP value for the given set of parameters.
     *
     * @param key        : the shared secret, HEX encoded
     * @param tm         : a value that reflects a time
     * @param codeDigits : number of digits to return
     * @param crypto     : the crypto function to use
     * @return a numeric String in base 10 that includes digits
     */

    private String generateTOTP(byte[] key, long tm, int codeDigits, String crypto) {
        StringBuilder result;

        // Allocating an array of bytes to represent the specified instant of time.
        byte[] data = new byte[8];
        long value = tm;

        // Converting the instant of time from the long representation to a
        // big-endian array of bytes (RFC4226, 5.2. Description).
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        byte[] hash = hmacSha(crypto, key, data);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        int otp = binary % ((int) Math.pow(10, codeDigits));

        result = new StringBuilder(Integer.toString(otp));
        while (result.length() < codeDigits) {
            result.insert(0, "0");
        }
        return result.toString();
    }

}
