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
package be.atbash.ee.security.octopus.realm.remember;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.crypto.AESCipherService;
import be.atbash.ee.security.octopus.crypto.CipherService;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.SubjectContext;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.RememberMeAuthenticationToken;
import be.atbash.util.codec.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract implementation of the {@code RememberMeManager} interface that handles
 * serialization (through DefaultSerializer) and encryption (through CipherService) of the remembered user identity.
 * <p/>
 * The remembered identity storage location and details are left to subclasses.
 * <h2>Default encryption key</h2>
 * This implementation uses an {@link AESCipherService AesCipherService} for strong encryption by default.  It also
 * uses a default generated symmetric key to both encrypt and decrypt data.  As AES is a symmetric cipher, the same
 * {@code key} is used to both encrypt and decrypt data, BUT NOTE:
 * <p/>
 * Because Shiro is an open-source project, if anyone knew that you were using Shiro's default
 * {@code key}, they could download/view the source, and with enough effort, reconstruct the {@code key}
 * and decode encrypted data at will.
 * <p/>
 * Of course, this key is only really used to encrypt the remembered {@code PrincipalCollection} which is typically
 * a user id or username.  So if you do not consider that sensitive information, and you think the default key still
 * makes things 'sufficiently difficult', then you can ignore this issue.
 * <p/>
 * However, if you do feel this constitutes sensitive information, it is recommended that you provide your own
 * {@code key} via the {@link #setCipherKey setCipherKey} method to a key known only to your application,
 * guaranteeing that no third party can decrypt your data.  You can generate your own key by calling the
 * {@code CipherService}'s {@link AESCipherService#generateNewKey() generateNewKey} method
 * and using that result as the {@link #setCipherKey cipherKey} configuration attribute.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.mgt.AbstractRememberMeManager"})
public abstract class AbstractRememberMeManager implements RememberMeManager {

    // FIXME Support for Java SE

    /**
     * private inner log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(AbstractRememberMeManager.class);

    /**
     * Serializer to use for converting PrincipalCollection instances to/from byte arrays
     */
    private DefaultSerializer serializer;

    /**
     * Cipher to use for encrypting/decrypting serialized byte arrays for added security
     */
    private CipherService cipherService;

    /**
     * Cipher encryption key to use with the Cipher when encrypting data
     */
    private byte[] encryptionCipherKey;

    /**
     * Cipher decryption key to use with the Cipher when decrypting data
     */
    private byte[] decryptionCipherKey;

    /**
     * Default constructor that initializes a {@link DefaultSerializer} as the serializer and
     * an {@link AESCipherService} as the  cipherService.
     */
    public AbstractRememberMeManager() {
        this.serializer = new DefaultSerializer();
        // FIXME Support for another service (asymmetric services for example)
        this.cipherService = new AESCipherService();
    }


    /**
     * Sets the encryption key to use for encryption operations.
     *
     * @param encryptionCipherKey the encryption key to use for encryption operations.
     */
    public void setEncryptionCipherKey(byte[] encryptionCipherKey) {
        this.encryptionCipherKey = encryptionCipherKey;
    }

    /**
     * Returns the decryption cipher key to use for decryption operations.
     *
     * @return the cipher key to use for decryption operations.
     */
    public byte[] getDecryptionCipherKey() {
        return decryptionCipherKey;
    }

    /**
     * Sets the decryption key to use for decryption operations.
     *
     * @param decryptionCipherKey the decryption key to use for decryption operations.
     */
    public void setDecryptionCipherKey(byte[] decryptionCipherKey) {
        this.decryptionCipherKey = decryptionCipherKey;
    }


    /**
     * Convenience method that sets the cipher key to use for <em>both</em> encryption and decryption.
     * <p/>
     * <b>N.B.</b> This method can only be called if the underlying cipherService is a
     * symmetric CipherService which by definition uses the same key for both encryption and decryption.  If using an
     * asymmetric CipherService (such as a public/private key pair), you cannot use this method, and should instead use
     * the {@link #setEncryptionCipherKey(byte[])} and {@link #setDecryptionCipherKey(byte[])} methods individually.
     * <p/>
     * The default {@link AESCipherService} instance is a symmetric CipherService, so this method can be used if you
     * are using the default.
     *
     * @param cipherKey the symmetric cipher key to use for both encryption and decryption.
     */
    public void setCipherKey(byte[] cipherKey) {
        //Since this method should only be used in symmetric ciphers
        //(where the enc and dec keys are the same), set it on both:
        setEncryptionCipherKey(cipherKey);
        setDecryptionCipherKey(cipherKey);
    }

    /**
     * Forgets (removes) any remembered identity data for the specified {@link Subject} instance.
     *
     * @param subject the subject instance for which identity data should be forgotten from the underlying persistence
     *                mechanism.
     */
    protected abstract void forgetIdentity(Subject subject);

    /**
     * Determines whether or not remember me services should be performed for the specified token.  This method returns
     * {@code true} iff:
     * <ol>
     * <li>The token is not {@code null} and</li>
     * <li>The token is an {@code instanceof} {@link RememberMeAuthenticationToken} and</li>
     * <li>{@code token}.{@link RememberMeAuthenticationToken#isRememberMe() isRememberMe()} is
     * {@code true}</li>
     * </ol>
     *
     * @param token the authentication token submitted during the successful authentication attempt.
     * @return true if remember me services should be performed as a result of the successful authentication attempt.
     */
    protected boolean isRememberMe(AuthenticationToken token) {
        return (token instanceof RememberMeAuthenticationToken) &&
                ((RememberMeAuthenticationToken) token).isRememberMe();
    }

    /**
     * Reacts to the successful login attempt by first always {@link #forgetIdentity(Subject) forgetting} any previously
     * stored identity.  Then if the {@code token}
     * {@link #isRememberMe(AuthenticationToken) is a RememberMe} token, the associated identity
     * will be {@link #rememberIdentity(Subject, AuthenticationToken, AuthenticationInfo) remembered}
     * for later retrieval during a new user session.
     *
     * @param subject the subject for which the principals are being remembered.
     * @param token   the token that resulted in a successful authentication attempt.
     * @param info    the authentication info resulting from the successful authentication attempt.
     */
    public void onSuccessfulLogin(Subject subject, AuthenticationToken token, AuthenticationInfo info) {
        //always clear any previous identity:
        forgetIdentity(subject);

        //now save the new identity:
        if (isRememberMe(token)) {
            rememberIdentity(subject, token, info);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("AuthenticationToken did not indicate RememberMe is requested.  " +
                        "RememberMe functionality will not be executed for corresponding account.");
            }
        }
    }

    /**
     * Remembers a subject-unique identity for retrieval later.  This implementation first
     * {@link #getIdentityToRemember resolves} the exact
     * {@link PrincipalCollection principals} to remember.  It then remembers the principals by calling
     * {@link #rememberIdentity(Subject, PrincipalCollection)}.
     * <p/>
     * This implementation ignores the {@link AuthenticationToken} argument, but it is available to subclasses if
     * necessary for custom logic.
     *
     * @param subject   the subject for which the principals are being remembered.
     * @param token     the token that resulted in a successful authentication attempt.
     * @param authcInfo the authentication info resulting from the successful authentication attempt.
     */
    public void rememberIdentity(Subject subject, AuthenticationToken token, AuthenticationInfo authcInfo) {
        PrincipalCollection principals = getIdentityToRemember(subject, authcInfo);
        rememberIdentity(subject, principals);
    }

    /**
     * Returns {@code info}.{@link AuthenticationInfo#getPrincipals() getPrincipals()} and
     * ignores the {@link Subject} argument.
     *
     * @param subject the subject for which the principals are being remembered.
     * @param info    the authentication info resulting from the successful authentication attempt.
     * @return the {@code PrincipalCollection} to remember.
     */
    protected PrincipalCollection getIdentityToRemember(Subject subject, AuthenticationInfo info) {
        return info.getPrincipals();
    }

    /**
     * Remembers the specified account principals by first
     * {@link #convertPrincipalsToBytes(PrincipalCollection) converting} them to a byte
     * array and then {@link #rememberSerializedIdentity(Subject, byte[]) remembers} that
     * byte array.
     *
     * @param subject           the subject for which the principals are being remembered.
     * @param accountPrincipals the principals to remember for retrieval later.
     */
    protected void rememberIdentity(Subject subject, PrincipalCollection accountPrincipals) {
        byte[] bytes = convertPrincipalsToBytes(accountPrincipals);
        rememberSerializedIdentity(subject, bytes);
    }

    /**
     * Converts the given principal collection the byte array that will be persisted to be 'remembered' later.
     * <p/>
     * This implementation first {@link #serialize(PrincipalCollection) serializes} the
     * principals to a byte array and then {@link #encrypt(byte[]) encrypts} that byte array.
     *
     * @param principals the {@code PrincipalCollection} to convert to a byte array
     * @return the representative byte array to be persisted for remember me functionality.
     */
    protected byte[] convertPrincipalsToBytes(PrincipalCollection principals) {
        byte[] bytes = serialize(principals);
        if (cipherService != null) {
            bytes = encrypt(bytes);
        }
        return bytes;
    }

    /**
     * Persists the identity bytes to a persistent store for retrieval later via the
     * {@link #getRememberedSerializedIdentity(SubjectContext)} method.
     *
     * @param subject    the Subject for which the identity is being serialized.
     * @param serialized the serialized bytes to be persisted.
     */
    protected abstract void rememberSerializedIdentity(Subject subject, byte[] serialized);

    /**
     * Implements the interface method by first {@link #getRememberedSerializedIdentity(SubjectContext) acquiring}
     * the remembered serialized byte array.  Then it {@link #convertBytesToPrincipals(byte[], SubjectContext) converts}
     * them and returns the re-constituted {@link PrincipalCollection}.  If no remembered principals could be
     * obtained, {@code null} is returned.
     * <p/>
     * If any exceptions are thrown, the {@link #onRememberedPrincipalFailure(RuntimeException, SubjectContext)} method
     * is called to allow any necessary post-processing (such as immediately removing any previously remembered
     * values for safety).
     *
     * @param subjectContext the contextual data, usually provided by a {@link Subject.Builder} implementation, that
     *                       is being used to construct a {@link Subject} instance.
     * @return the remembered principals or {@code null} if none could be acquired.
     */
    public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
        PrincipalCollection principals = null;
        try {
            byte[] bytes = getRememberedSerializedIdentity(subjectContext);
            //SHIRO-138 - only call convertBytesToPrincipals if bytes exist:
            if (bytes != null && bytes.length > 0) {
                principals = convertBytesToPrincipals(bytes, subjectContext);
            }
        } catch (RuntimeException re) {
            principals = onRememberedPrincipalFailure(re, subjectContext);
        }

        return principals;
    }

    /**
     * Based on the given subject context data, retrieves the previously persisted serialized identity, or
     * {@code null} if there is no available data.  The context map is usually populated by a {@link Subject.Builder}
     * implementation.  See the {@link SubjectFactory} class constants for Shiro's known map keys.
     *
     * @param subjectContext the contextual data, usually provided by a {@link Subject.Builder} implementation, that
     *                       is being used to construct a {@link Subject} instance.  To be used to assist with data
     *                       lookup.
     * @return the previously persisted serialized identity, or {@code null} if there is no available data for the
     * Subject.
     */
    protected abstract byte[] getRememberedSerializedIdentity(SubjectContext subjectContext);

    /**
     * If a cipherService is available, it will be used to first decrypt the byte array.
     * Then the bytes are then {@link #deserialize(byte[]) deserialized} and then returned.
     *
     * @param bytes          the bytes to decrypt if necessary and then deserialize.
     * @param subjectContext the contextual data, usually provided by a {@link Subject.Builder} implementation, that
     *                       is being used to construct a {@link Subject} instance.
     * @return the de-serialized and possibly decrypted principals
     */
    protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
        if (cipherService != null) {
            bytes = decrypt(bytes);
        }
        return deserialize(bytes);
    }

    /**
     * Called when an exception is thrown while trying to retrieve principals.  The default implementation logs a
     * warning message and forgets ('unremembers') the problem identity by calling
     * {@link #forgetIdentity(SubjectContext) forgetIdentity(context)} and then immediately re-throws the
     * exception to allow the calling component to react accordingly.
     * <p/>
     * This method implementation never returns an
     * object - it always rethrows, but can be overridden by subclasses for custom handling behavior.
     * <p/>
     * This most commonly would be called when an encryption key is updated and old principals are retrieved that have
     * been encrypted with the previous key.
     *
     * @param e       the exception that was thrown.
     * @param context the contextual data, usually provided by a {@link Subject.Builder} implementation, that
     *                is being used to construct a {@link Subject} instance.
     * @return nothing - the original {@code RuntimeException} is propagated in all cases.
     */
    protected PrincipalCollection onRememberedPrincipalFailure(RuntimeException e, SubjectContext context) {

        if (log.isWarnEnabled()) {
            String message = "There was a failure while trying to retrieve remembered principals.  This could be due to a " +
                    "configuration problem or corrupted principals.  This could also be due to a recently " +
                    "changed encryption key, if you are using a shiro.ini file, this property would be " +
                    "'securityManager.rememberMeManager.cipherKey' see: http://shiro.apache.org/web.html#Web-RememberMeServices. " +
                    "The remembered identity will be forgotten and not used for this request.";
            log.warn(message);
        }
        forgetIdentity(context);
        //propagate - security manager implementation will handle and warn appropriately
        throw e;
    }

    /**
     * Encrypts the byte array by using the configured cipherService.
     *
     * @param serialized the serialized object byte array to be encrypted
     * @return an encrypted byte array returned by the configured CipherService.
     */
    protected byte[] encrypt(byte[] serialized) {
        byte[] value = serialized;
        if (cipherService != null) {
            ByteSource byteSource = cipherService.encrypt(serialized, encryptionCipherKey);
            value = byteSource.getBytes();
        }
        return value;
    }

    /**
     * Decrypts the byte array using the configured CipherService.
     *
     * @param encrypted the encrypted byte array to decrypt
     * @return the decrypted byte array returned by the configured CipherService.
     */
    protected byte[] decrypt(byte[] encrypted) {
        byte[] serialized = encrypted;
        if (cipherService != null) {
            ByteSource byteSource = cipherService.decrypt(encrypted, getDecryptionCipherKey());
            serialized = byteSource.getBytes();
        }
        return serialized;
    }

    /**
     * Serializes the given {@code principals} by serializing them to a byte array by using the
     * serializer's serialize(Object) serialize method.
     *
     * @param principals the principal collection to serialize to a byte array
     * @return the serialized principal collection in the form of a byte array
     */
    protected byte[] serialize(PrincipalCollection principals) {
        return serializer.serialize(principals);
    }

    /**
     * De-serializes the given byte array by using the serializer's
     * deserialize method.
     *
     * @param serializedIdentity the previously serialized {@code PrincipalCollection} as a byte array
     * @return the de-serialized (reconstituted) {@code PrincipalCollection}
     */
    protected PrincipalCollection deserialize(byte[] serializedIdentity) {
        return serializer.deserialize(serializedIdentity);
    }

    /**
     * Reacts to a failed login by immediately {@link #forgetIdentity(Subject) forgetting} any
     * previously remembered identity.  This is an additional security feature to prevent any remenant identity data
     * from being retained in case the authentication attempt is not being executed by the expected user.
     *
     * @param subject the subject which executed the failed login attempt
     * @param token   the authentication token resulting in a failed login attempt - ignored by this implementation
     * @param ae      the exception thrown as a result of the failed login attempt - ignored by this implementation
     */
    public void onFailedLogin(Subject subject, AuthenticationToken token, AuthenticationException ae) {
        forgetIdentity(subject);
    }

    /**
     * Reacts to a subject logging out of the application and immediately
     * {@link #forgetIdentity(Subject) forgets} any previously stored identity and returns.
     *
     * @param subject the subject logging out.
     */
    public void onLogout(Subject subject) {
        forgetIdentity(subject);
    }
}