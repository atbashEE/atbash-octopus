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


import be.atbash.ee.security.octopus.otp.OTPProvider;
import be.atbash.ee.security.octopus.otp.OTPUserData;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

/**
 *
 */
public class HOTPProvider implements OTPProvider {

    private static final String TRUNCATE_OFFSET = "truncate_offset";
    private static final String CHECKSUM = "checksum";

    /**
     * a flag that indicates if a checksum digit
     * <p>
     * M'Raihi, et al. Informational [Page 29]
     * <p>
     * RFC 4226 HOTP Algorithm December 2005
     * <p>
     * should be appended to the OTP.
     */
    private boolean addChecksum = false;
    /**
     * the offset into the MAC result to begin truncation. If this
     * value is out of the range of 0 ... 15, then dynamic truncation
     * will be used. Dynamic truncation is when the last 4 bits of
     * the last byte of the MAC are used to determine the start
     * offset.
     */
    private int truncationOffset = 0;
    private int digits;
    private Properties properties;

    @Override
    public void setProperties(int digits, Properties properties) {
        this.digits = digits;
        this.properties = properties;
    }

    @Override
    public String generate(OTPUserData data) {
        addChecksum = false;
        truncationOffset = 0;

        if (properties.containsKey(CHECKSUM)) {
            addChecksum = Boolean.parseBoolean(properties.get(CHECKSUM).toString());
        }

        if (properties.containsKey(TRUNCATE_OFFSET)) {
            truncationOffset = Integer.parseInt(properties.get(TRUNCATE_OFFSET).toString());
        }

        try {
            Long value = data.getValue();
            if (value == null) {
                value = 0L;
            }
            long base = value + 1;
            data.setValue(base);
            return generateOTP(data.getKey(), base);
        } catch (Exception e) {
            throw new AtbashUnexpectedException(e);
        }

    }

    @Override
    public boolean supportValidate() {
        return true;
    }

    @Override
    public boolean valid(OTPUserData data, int window, String userOTP) {
        boolean result = false;
        for (int i = -window; i < window; i++) {
            if (data.getValue() == null) {
                // This is a developer error, so we can do this.
                throw new IllegalArgumentException("OTPUserData.value needs to contain the latest counter");
            }
            String code = generateOTP(data.getKey(), data.getValue() + i);
            if (code.equals(userOTP)) {
                result = true;
            }
            break;   // TODO Where does this come from and why do we need it?
        }
        return result;
    }

    // These are used to calculate the check-sum digits.
    // 0 1 2 3 4 5 6 7 8 9
    private static final int[] doubleDigits = {0, 2, 4, 6, 8, 1, 3, 5, 7, 9};

    /**
     * Calculates the checksum using the credit card algorithm. This algorithm
     * has the advantage that it detects any single mistyped digit and any
     * single transposition of adjacent digits.
     *
     * @param num    the number to calculate the checksum for
     * @param digits number of significant places in the number
     * @return the checksum of num
     */
    private int calcChecksum(long num, int digits) {
        boolean doubleDigit = true;
        int total = 0;
        while (0 < digits--) {
            int digit = (int) (num % 10);
            num /= 10;
            if (doubleDigit) {
                digit = doubleDigits[digit];
            }
            total += digit;
            doubleDigit = !doubleDigit;
        }
        int result = total % 10;
        if (result > 0) {
            result = 10 - result;
        }
        return result;
    }

    /**
     * This method uses the JCE to provide the HMAC-SHA-1
     * <p>
     * <p>
     * <p>
     * M'Raihi, et al. Informational [Page 28]
     * <p>
     * RFC 4226 HOTP Algorithm December 2005
     * <p>
     * <p>
     * algorithm. HMAC computes a Hashed Message Authentication Code and in this
     * case SHA1 is the hash algorithm used.
     *
     * @param keyBytes the bytes to use for the HMAC-SHA-1 key
     * @param text     the message or text to be authenticated.
     */

    private byte[] hmacSha1(byte[] keyBytes, byte[] text) {
        try {
            Mac hmacSha1;
            try {
                hmacSha1 = Mac.getInstance("HmacSHA1");
            } catch (NoSuchAlgorithmException nsae) {
                hmacSha1 = Mac.getInstance("HMAC-SHA-1");
            }
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmacSha1.init(macKey);
            return hmacSha1.doFinal(text);
        } catch (NoSuchAlgorithmException e) {
            throw new AtbashUnexpectedException(e);
        } catch (InvalidKeyException e) {
            throw new AtbashUnexpectedException(e); // TODO Is this correct
        }
    }

    /**
     * This method generates an OTP value for the given set of parameters.
     *
     * @param secret       the shared secret
     * @param movingFactor the counter, time, or other value that changes on a per use
     *                     basis.
     * @return A numeric String in base 10 that includes digits plus the optional checksum digit if requested.
     */
    private String generateOTP(byte[] secret, long movingFactor) {
        StringBuilder result;
        int codeDigits = digits;

        // put movingFactor value into text byte array
        int digits = addChecksum ? (codeDigits + 1) : codeDigits;
        byte[] text = new byte[8];
        for (int i = text.length - 1; i >= 0; i--) {
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }

        // compute hmac hash
        byte[] hash = hmacSha1(secret, text);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;
        if ((0 <= truncationOffset) && (truncationOffset < (hash.length - 4))) {
            offset = truncationOffset;
        }
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        int otp = binary % ((int) Math.pow(10, codeDigits));
        if (addChecksum) {
            otp = (otp * 10) + calcChecksum(otp, codeDigits);
        }
        result = new StringBuilder(Integer.toString(otp));
        while (result.length() < digits) {
            result.insert(0, "0");
        }
        return result.toString();
    }

}
