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
package be.atbash.ee.security.octopus.authc.credential;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.crypto.hash.Hash;
import be.atbash.ee.security.octopus.crypto.hash.HashFactory;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.util.codec.CodecSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Simple CredentialsMatcher implementation.  Supports direct (plain) comparison for credentials of type
 * byte[], char[], and Strings, and if the arguments do not match these types, then reverts back to simple
 * <code>Object.equals</code> comparison.
 * <p/>
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authc.credential.SimpleCredentialsMatcher", "org.apache.shiro.authc.credential.HashedCredentialsMatcher"})
// TODO Do we need protected methods so that we can override
public class DefaultCredentialsMatcher extends CodecSupport implements CredentialsMatcher {

    private static final Logger log = LoggerFactory.getLogger(DefaultCredentialsMatcher.class);

    private OctopusCoreConfiguration octopusCoreConfiguration = OctopusCoreConfiguration.getInstance();

    private HashFactory hashFactory = HashFactory.getInstance();

    /**
     * Returns the {@code account}'s credentials.
     * <p/>
     * <p>This default implementation merely returns
     * {@link AuthenticationInfo#getCredentials() account.getCredentials()} and exists as a template hook if subclasses
     * wish to obtain the credentials in a different way or convert them to a different format before
     * returning.
     *
     * @param info the {@code AuthenticationInfo} stored in the data store to be compared against the submitted authentication
     *             token's credentials.
     * @return the {@code account}'s associated credentials.
     */
    private Object getCredentials(AuthenticationInfo info) {
        return info.getCredentials();
    }

    /**
     * Returns {@code true} if the {@code tokenCredentials} argument is logically equal to the
     * {@code accountCredentials} argument.
     * <p/>
     * <p>If both arguments are either a byte array (byte[]), char array (char[]) or String, they will be both be
     * converted to raw byte arrays via the {@link #toBytes toBytes} method first, and then resulting byte arrays
     * are compared via {@link Arrays#equals(byte[], byte[]) Arrays.equals(byte[],byte[])}.</p>
     * <p/>
     * <p>If either argument cannot be converted to a byte array as described, a simple Object <code>equals</code>
     * comparison is made.</p>
     * <p/>
     * <p>Subclasses should override this method for more explicit equality checks.
     *
     * @param tokenCredentials   the {@code AuthenticationToken}'s associated credentials.
     * @param accountCredentials the {@code AuthenticationInfo}'s stored credentials.
     * @return {@code true} if the {@code tokenCredentials} are equal to the {@code accountCredentials}.
     */
    private boolean equals(Object tokenCredentials, Object accountCredentials) {
        if (tokenCredentials == null || accountCredentials == null) {
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Performing credentials equality check for tokenCredentials of type [" +
                    tokenCredentials.getClass().getName() + " and accountCredentials of type [" +
                    accountCredentials.getClass().getName() + "]");
        }
        if (isByteSource(tokenCredentials) && isByteSource(accountCredentials)) {
            if (log.isDebugEnabled()) {
                log.debug("Both credentials arguments can be easily converted to byte arrays.  Performing " +
                        "array equals comparison");
            }
            byte[] tokenBytes = toBytes(tokenCredentials);
            byte[] accountBytes = toBytes(accountCredentials);
            return MessageDigest.isEqual(tokenBytes, accountBytes);
        } else {
            return accountCredentials.equals(tokenCredentials);
        }
    }

    /**
     * This implementation acquires the {@code token}'s credentials
     * and then the {@code account}'s credentials and then passes both of
     * them to the {@link #equals(Object, Object) equals(tokenCredentials, accountCredentials)} method for equality
     * comparison.
     *
     * @param token the {@code AuthenticationToken} submitted during the authentication attempt.
     * @param info  the {@code AuthenticationInfo} stored in the system matching the token principal.
     * @return {@code true} if the provided token credentials are equal to the stored account credentials,
     * {@code false} otherwise
     */
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        Object tokenCredentials;
        if (info.isHashedPassword()) {

            Hash hash = hashFactory.defineHash(octopusCoreConfiguration.getHashAlgorithmName(), token.getCredentials(), info.getCredentialsSalt(), octopusCoreConfiguration.getHashIterations());
            switch (octopusCoreConfiguration.getHashEncoding()) {

                case HEX:
                    tokenCredentials = hash.toHex();
                    break;
                case BASE64:
                    tokenCredentials = hash.toBase64();
                    break;
                default:
                    throw new IllegalArgumentException(String.format("Unsupported Hash encoding %s", octopusCoreConfiguration.getHashEncoding()));
            }

        } else {
            tokenCredentials = token.getCredentials();
        }
        Object accountCredentials = getCredentials(info);
        return equals(tokenCredentials, accountCredentials);
    }

}
