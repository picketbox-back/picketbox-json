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

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.picketbox.json.PicketBoxJSONMessages;
import org.picketbox.json.exceptions.ProcessingException;

/**
 * Utility for encryption
 *
 * @author anil saldhana
 * @since Jul 30, 2012
 */
public class EncUtil {
    public static final String AES = "AES";
    public static final String AES_CBC = "AES/CBC/PKCS5Padding";
    public static final String SHA_256 = "SHA-256";

    public static byte[] encryptUsingAES_CBC(String plainText, byte[] key, IvParameterSpec parameters)
            throws ProcessingException {
        if (key == null || key.length == 0) {
            throw PicketBoxJSONMessages.MESSAGES.invalidNullArgument("key");
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(AES_CBC);
            SecretKeySpec keyspec = new SecretKeySpec(key, AES);
            cipher.init(Cipher.ENCRYPT_MODE, keyspec, parameters);
            return cipher.doFinal(plainText.getBytes());
        } catch (Exception e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }

    public static byte[] decryptUsingAES_CBC(byte[] encryptedPlainText, byte[] key, IvParameterSpec parameters)
            throws ProcessingException {
        if (key == null || key.length == 0) {
            throw PicketBoxJSONMessages.MESSAGES.invalidNullArgument("key");
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(AES_CBC);
            SecretKeySpec keyspec = new SecretKeySpec(key, AES);
            cipher.init(Cipher.DECRYPT_MODE, keyspec, parameters);
            return cipher.doFinal(encryptedPlainText);
        } catch (Exception e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }
}