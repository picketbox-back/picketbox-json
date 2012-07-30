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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.picketbox.json.PicketBoxJSONMessages;
import org.picketbox.json.exceptions.ProcessingException;

/**
 * <p>
 * Approved Alternative 1 : Concatenation Key Derivation Function
 * </p>
 * <p>
 * Document: Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography
 * </p>
 * <p>
 * Location: http://csrc.nist.gov/publications/PubsSPs.html SP 800-56A
 * </p>
 *
 * @author anil saldhana
 * @since Jul 27, 2012
 */
public class ConcatenationKeyDerivation {
    private final long MAX_HASH_INPUTLEN = Long.MAX_VALUE;
    private final long UNSIGNED_INTEGER_MAX_VALUE = 4294967295L;
    private MessageDigest md;

    public ConcatenationKeyDerivation(String hashAlg) throws ProcessingException {
        try {
            md = MessageDigest.getInstance(hashAlg);
        } catch (NoSuchAlgorithmException e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }

    public byte[] concatKDF(byte[] z, int keyDataLen, byte[] algorithmID, byte[] partyUInfo, byte[] partyVInfo,
            byte[] suppPubInfo, byte[] suppPrivInfo) {
        int hashLen = md.getDigestLength() * 8;

        if (keyDataLen % 8 != 0) {
            throw PicketBoxJSONMessages.MESSAGES.keyDataLenError();
        }

        if (keyDataLen > (long) hashLen * UNSIGNED_INTEGER_MAX_VALUE) {
            throw PicketBoxJSONMessages.MESSAGES.keyDataLenLarge();
        }
        if (algorithmID == null) {
            throw PicketBoxJSONMessages.MESSAGES.invalidNullArgument("algorithmID");
        }

        if (partyUInfo == null) {
            throw PicketBoxJSONMessages.MESSAGES.invalidNullArgument("partyUInfo");
        }

        if (partyVInfo == null) {
            throw PicketBoxJSONMessages.MESSAGES.invalidNullArgument("partyVInfo");
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(algorithmID);
            baos.write(partyUInfo);
            baos.write(partyVInfo);
            if (suppPubInfo != null) {
                baos.write(suppPubInfo);
            }
            if (suppPrivInfo != null) {
                baos.write(suppPrivInfo);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        byte[] otherInfo = baos.toByteArray();
        return concatKDF(z, keyDataLen, otherInfo);
    }

    /**
     * Generate a KDF
     *
     * @param z shared secret
     * @param keyDataLen
     * @param otherInfo
     * @return
     */
    public byte[] concatKDF(byte[] z, int keyDataLen, byte[] otherInfo) {
        byte[] key = new byte[keyDataLen];

        int hashLen = md.getDigestLength();
        int reps = keyDataLen / hashLen;

        if (reps > UNSIGNED_INTEGER_MAX_VALUE) {
            throw new IllegalArgumentException("Key derivation failed");
        }

        // First check on the overall hash length
        int counter = 1;
        byte[] fourByteInt = convertIntegerToFourBytes(counter);

        if ((fourByteInt.length + z.length + otherInfo.length) * 8 > MAX_HASH_INPUTLEN) {
            throw PicketBoxJSONMessages.MESSAGES.hashLengthTooLarge();
        }

        for (int i = 0; i <= reps; i++) {
            md.reset();
            md.update(convertIntegerToFourBytes(i + 1));
            md.update(z);
            md.update(otherInfo);

            byte[] hash = md.digest();
            if (i < reps) {
                System.arraycopy(hash, 0, key, hashLen * i, hashLen);
            } else {
                System.arraycopy(hash, 0, key, hashLen * i, keyDataLen % hashLen);
            }
        }
        return key;
    }

    private byte[] convertIntegerToFourBytes(int i) {
        byte[] res = new byte[4];
        res[0] = (byte) (i >>> 24);
        res[1] = (byte) ((i >>> 16) & 0xFF);
        res[2] = (byte) ((i >>> 8) & 0xFF);
        res[3] = (byte) (i & 0xFF);
        return res;
    }
}