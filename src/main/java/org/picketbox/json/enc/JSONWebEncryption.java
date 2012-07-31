/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketbox.json.enc;

import static org.picketbox.json.PicketBoxJSONConstants.COMMON.PERIOD;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;
import org.json.JSONException;
import org.picketbox.json.PicketBoxJSONMessages;
import org.picketbox.json.exceptions.ProcessingException;
import org.picketbox.json.util.Base64;
import org.picketbox.json.util.PicketBoxJSONUtil;

/**
 * Represents JSON Web Encryption http://tools.ietf.org/html/draft-jones-json-web-encryption
 *
 * @author anil saldhana
 * @since Jul 27, 2012
 */
public class JSONWebEncryption {
    protected JSONWebEncryptionHeader jsonWebEncryptionHeader;

    /**
     * Create an attached Header
     *
     * @return
     */
    public JSONWebEncryptionHeader createHeader() {
        if (jsonWebEncryptionHeader == null) {
            jsonWebEncryptionHeader = new JSONWebEncryptionHeader();
        }
        return jsonWebEncryptionHeader;
    }

    /**
     * Get the {@link JSONWebEncryptionHeader}
     *
     * @return
     */
    public JSONWebEncryptionHeader getJsonWebEncryptionHeader() {
        return jsonWebEncryptionHeader;
    }

    /**
     * Set the {@link JSONWebEncryptionHeader}
     *
     * @param jsonWebEncryptionHeader
     */
    public void setJsonWebEncryptionHeader(JSONWebEncryptionHeader jsonWebEncryptionHeader) {
        this.jsonWebEncryptionHeader = jsonWebEncryptionHeader;
    }

    /**
     * Encrypt
     *
     * @param plainText
     * @param recipientPublicKey
     * @return
     * @throws ProcessingException
     */
    public String encrypt(String plainText, PublicKey recipientPublicKey) throws ProcessingException {
        if (jsonWebEncryptionHeader == null) {
            throw PicketBoxJSONMessages.MESSAGES.jsonEncryptionHeaderMissing();
        }
        if (plainText == null) {
            throw PicketBoxJSONMessages.MESSAGES.invalidNullArgument("plainText");
        }
        if (recipientPublicKey == null) {
            throw PicketBoxJSONMessages.MESSAGES.invalidNullArgument("recipientPublicKey");
        }
        byte[] contentMasterKey = createContentMasterKey();
        return encrypt(plainText, recipientPublicKey, contentMasterKey);
    }

    /**
     * Encrypt
     *
     * @param plainText
     * @param recipientPublicKey
     * @param contentMasterKey
     * @return
     * @throws ProcessingException
     */
    public String encrypt(String plainText, PublicKey recipientPublicKey, byte[] contentMasterKey) throws ProcessingException {
        if (jsonWebEncryptionHeader == null) {
            throw PicketBoxJSONMessages.MESSAGES.jsonEncryptionHeaderMissing();
        }
        if (plainText == null) {
            throw PicketBoxJSONMessages.MESSAGES.invalidNullArgument("plainText");
        }
        if (recipientPublicKey == null) {
            throw PicketBoxJSONMessages.MESSAGES.invalidNullArgument("recipientPublicKey");
        }
        if (contentMasterKey == null) {
            return encrypt(plainText, recipientPublicKey);
        }

        SecretKey contentEncryptionKey = new SecretKeySpec(contentMasterKey, EncUtil.AES);

        // Encrypt using Recipient's public key to yield JWE Encrypted Key
        byte[] jweEncryptedKey = encryptKey(recipientPublicKey, contentMasterKey);
        String encodedJWEKey = PicketBoxJSONUtil.b64Encode(jweEncryptedKey);

        StringBuilder builder = new StringBuilder(PicketBoxJSONUtil.b64Encode(jsonWebEncryptionHeader.toString()));
        builder.append(PERIOD);
        builder.append(encodedJWEKey);

        if (jsonWebEncryptionHeader.needIntegrity()) {
            int cekLength = jsonWebEncryptionHeader.getCEKLength();
            byte[] cek = generateCEK(contentEncryptionKey.getEncoded(), cekLength);

            // Deal with IV
            String iv;
            try {
                iv = jsonWebEncryptionHeader.getDelegate().getString("iv");
            } catch (JSONException e) {
                throw PicketBoxJSONMessages.MESSAGES.ignorableError(e);
            }
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());

            byte[] encryptedText = EncUtil.encryptUsingAES_CBC(plainText, cek, ivParameterSpec);
            String encodedJWEText = PicketBoxJSONUtil.b64Encode(encryptedText);
            builder.append(PERIOD);
            builder.append(encodedJWEText);

            int cikLength = jsonWebEncryptionHeader.getCIKLength();
            byte[] cik = generateCIK(contentEncryptionKey.getEncoded(), cikLength);
            byte[] integrityValue = performMac(cik, builder.toString().getBytes());
            String encodedIntegrityValue = PicketBoxJSONUtil.b64Encode(integrityValue);

            builder.append(PERIOD);
            builder.append(encodedIntegrityValue);
        } else {
            // Encrypt the plain text
            byte[] encryptedText = encryptText(plainText, recipientPublicKey);
            String encodedJWEText = PicketBoxJSONUtil.b64Encode(encryptedText);
            builder.append(PERIOD);
            builder.append(encodedJWEText);
        }

        return builder.toString();
    }

    /**
     * Decrypt using a {@link PrivateKey}
     *
     * @param encryptedText
     * @param privateKey
     * @return
     * @throws ProcessingException
     */
    public String decrypt(String encryptedText, PrivateKey privateKey) throws ProcessingException {
        try {
            String[] splitBits = encryptedText.split("\\.");
            int length = splitBits.length;
            String encodedHeader = splitBits[0];
            String encodedKey = splitBits[1];
            String encodedValue = splitBits[2];
            String encodedIntegrity = null;
            if (length == 4) {
                encodedIntegrity = splitBits[3];
            }

            String decodedHeader = new String(Base64.decode(encodedHeader));
            JSONWebEncryptionHeader header = new JSONWebEncryptionHeader();
            header.load(decodedHeader);

            if (header.needIntegrity()) {

                byte[] decodedKey = Base64.decode(encodedKey);

                byte[] secretKey = decryptKey(privateKey, decodedKey);

                int cekLength = header.getCEKLength();
                byte[] cek = generateCEK(secretKey, cekLength);

                // Deal with IV
                String iv;
                try {
                    iv = header.getDelegate().getString("iv");
                } catch (JSONException e) {
                    throw PicketBoxJSONMessages.MESSAGES.ignorableError(e);
                }

                IvParameterSpec ivParameter = new IvParameterSpec(iv.getBytes());

                byte[] decodedText = Base64.decode(encodedValue);
                byte[] plainText = EncUtil.decryptUsingAES_CBC(decodedText, cek, ivParameter);

                int cikLength = header.getCIKLength();
                byte[] cik = generateCIK(secretKey, cikLength);

                StringBuilder builder = new StringBuilder(PicketBoxJSONUtil.b64Encode(header.toString()));
                builder.append(PERIOD).append(encodedKey).append(PERIOD).append(encodedValue);

                byte[] integrityValue = performMac(cik, builder.toString().getBytes());
                String encodedIntegrityValue = PicketBoxJSONUtil.b64Encode(integrityValue);

                if (Arrays.constantTimeAreEqual(encodedIntegrityValue.getBytes(), encodedIntegrity.getBytes())) {
                    return new String(plainText);
                } else {
                    throw new RuntimeException("Integrity Checks Failed");
                }
            }

            Cipher textCipher = header.getCipherBasedOnAlg();
            textCipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decodedText = Base64.decode(encodedValue);
            byte[] plainText = textCipher.doFinal(decodedText);

            return new String(plainText);
        } catch (Exception e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }

    private byte[] encryptText(String plainText, PublicKey recipientPublicKey) throws ProcessingException {
        try {
            Cipher cipher = jsonWebEncryptionHeader.getCipherBasedOnAlg();
            cipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);

            return cipher.doFinal(plainText.getBytes());
        } catch (Exception e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }

    private byte[] encryptKey(PublicKey publicKey, byte[] contentMasterKey) throws ProcessingException {
        try {
            Cipher cipher = jsonWebEncryptionHeader.getCipherBasedOnAlg();
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return cipher.doFinal(contentMasterKey);
        } catch (Exception e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }

    private byte[] decryptKey(PrivateKey privateKey, byte[] encryptedKey) throws ProcessingException {
        try {
            Cipher cipher = jsonWebEncryptionHeader.getCipherBasedOnAlg();
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            return cipher.doFinal(encryptedKey);
        } catch (Exception e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }

    /**
     * Generate a random byte array.
     *
     * @return
     */
    private byte[] createContentMasterKey() {
        return UUID.randomUUID().toString().getBytes();
    }

    private byte[] generateCIK(byte[] keyBytes, int cikByteLength) throws ProcessingException {
        // "Integrity"
        final byte[] otherInfo = { 73, 110, 116, 101, 103, 114, 105, 116, 121 };
        ConcatenationKeyDerivation kdfGen = new ConcatenationKeyDerivation(EncUtil.SHA_256);
        return kdfGen.concatKDF(keyBytes, cikByteLength, otherInfo);
    }

    private byte[] generateCEK(byte[] keyBytes, int cekByteLength) throws ProcessingException {
        // "Encryption"
        final byte[] otherInfo = { 69, 110, 99, 114, 121, 112, 116, 105, 111, 110 };
        ConcatenationKeyDerivation kdfGen = new ConcatenationKeyDerivation(EncUtil.SHA_256);
        return kdfGen.concatKDF(keyBytes, cekByteLength, otherInfo);
    }

    private byte[] performMac(byte[] key, byte[] data) throws ProcessingException {
        Mac mac = null;
        try {
            mac = Mac.getInstance(jsonWebEncryptionHeader.getMessageAuthenticationCodeAlgo());

            mac.init(new SecretKeySpec(key, mac.getAlgorithm()));
            mac.update(data);
            return mac.doFinal();
        } catch (Exception e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }
}