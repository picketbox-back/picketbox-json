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

import static org.picketbox.json.PicketBoxJSONConstants.COMMON.ALG;
import static org.picketbox.json.PicketBoxJSONConstants.COMMON.ENC;
import static org.picketbox.json.PicketBoxJSONConstants.JWE.ENC_ALG_A128CBC;
import static org.picketbox.json.PicketBoxJSONConstants.JWE.ENC_ALG_A192CBC;
import static org.picketbox.json.PicketBoxJSONConstants.JWE.ENC_ALG_A256CBC;
import static org.picketbox.json.PicketBoxJSONConstants.JWE.ENC_ALG_A512CBC;
import static org.picketbox.json.PicketBoxJSONConstants.JWS.SIGN_ALG_HS256;
import static org.picketbox.json.PicketBoxJSONConstants.JWS.SIGN_ALG_HS384;
import static org.picketbox.json.PicketBoxJSONConstants.JWS.SIGN_ALG_HS512;

import javax.crypto.Cipher;

import org.json.JSONException;
import org.json.JSONObject;
import org.picketbox.json.PicketBoxJSONConstants;
import org.picketbox.json.PicketBoxJSONMessages;
import org.picketbox.json.exceptions.ProcessingException;

/**
 * Represents the JSONWebEncryptionHeader
 *
 * @author anil saldhana
 * @since Jul 27, 2012
 */
public class JSONWebEncryptionHeader {
    private JSONObject delegate;

    /**
     * Get the underlying {@link JSONObject}
     *
     * @return
     */
    public JSONObject getDelegate() {
        return delegate;
    }

    /**
     * Set the underlying {@link JSONObject}
     *
     * @param delegate
     */
    public void setDelegate(JSONObject delegate) {
        this.delegate = delegate;
    }

    /**
     * Check if there is a need for integrity value
     *
     * @return
     */
    public boolean needIntegrity() {
        if (delegate != null)
            try {
                return delegate.getString("int") != null;
            } catch (JSONException e) {
                throw PicketBoxJSONMessages.MESSAGES.ignorableError(e);
            }
        else
            return false;
    }

    /**
     * Based on the alg entry, determine the {@link Cipher}
     *
     * @return
     * @throws ProcessingException
     */
    public Cipher getCipherBasedOnAlg() throws ProcessingException {
        try {
            if (delegate == null) {
                return Cipher.getInstance("RSA/ECB/PKCS1Padding");
            }

            if (PicketBoxJSONConstants.JWE.ENC_ALG_RSA_OAEP.equals(delegate.getString(ALG))) {
                return Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            } else if (PicketBoxJSONConstants.JWE.ENC_ALG_RSA1_5.equals(delegate.getString(ALG))) {
                return Cipher.getInstance("RSA/ECB/PKCS1Padding");
            }
        } catch (Exception e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
        return null;
    }

    /**
     * Based on the enc entry, determine the {@link Cipher}
     *
     * @return
     * @throws ProcessingException
     */
    public Cipher getCipherBasedOnEnc() throws ProcessingException {
        if (delegate != null) {
            String enc = null;
            try {
                enc = delegate.getString(ENC);
            } catch (JSONException e1) {
                throw PicketBoxJSONMessages.MESSAGES.ignorableError(e1);
            }
            if (enc.contains("CBC")) {
                try {
                    return Cipher.getInstance("AES/CBC/PKCS5Padding");
                } catch (Exception e) {
                    throw PicketBoxJSONMessages.MESSAGES.processingException(e);
                }
            }
        }
        return null;
    }

    /**
     * Get the CEK length
     *
     * @return
     */
    public int getCEKLength() {
        int cekLength = 128 / 8;
        if (delegate == null)
            return cekLength;

        String enc = null;
        try {
            enc = delegate.getString(ENC);
        } catch (JSONException e) {
            throw PicketBoxJSONMessages.MESSAGES.ignorableError(e);
        }
        if (ENC_ALG_A128CBC.equals(enc)) {
            cekLength = 128 / 8;
        } else if (ENC_ALG_A192CBC.equals(enc)) {
            cekLength = 192 / 8;
        } else if (ENC_ALG_A256CBC.equals(enc)) {
            cekLength = 256 / 8;
        } else if (ENC_ALG_A512CBC.equals(enc)) {
            cekLength = 512 / 8;
        }
        return cekLength;
    }

    /**
     * Get the CIK length
     *
     * @return
     */
    public int getCIKLength() {
        int cikLength = 256 / 8;
        if (delegate == null)
            return cikLength;

        String integrity = null;

        try {
            integrity = delegate.getString("int");
        } catch (JSONException e) {
            throw PicketBoxJSONMessages.MESSAGES.ignorableError(e);
        }

        if (SIGN_ALG_HS256.equals(integrity)) {
            cikLength = 256 / 8;
        } else if (SIGN_ALG_HS384.equals(integrity)) {
            cikLength = 384 / 8;
        } else if (SIGN_ALG_HS512.equals(integrity)) {
            cikLength = 512 / 8;
        }
        return cikLength;
    }

    /**
     * Get the Message Authentication Code algorithm
     *
     * @return
     */
    public String getMessageAuthenticationCodeAlgo() {
        String algo = "HMACSHA256";
        if (delegate == null)
            return algo;

        String integrity = null;

        try {
            integrity = delegate.getString("int");
        } catch (JSONException e) {
            throw PicketBoxJSONMessages.MESSAGES.ignorableError(e);
        }

        if ("HS256".equals(integrity)) { // HMAC SHA-256
            algo = "HMACSHA256";
        } else if ("HS384".equals(integrity)) { // HMAC SHA-384
            algo = "HMACSHA384";
        } else if ("HS512".equals(integrity)) { // HMAC SHA-512
            algo = "HMACSHA512";
        }
        return algo;
    }

    /**
     * Given a JSON String, load internals
     *
     * @param json
     * @throws ProcessingException
     */
    public void load(String json) throws ProcessingException {
        try {
            this.delegate = new JSONObject(json);
        } catch (JSONException j) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(j);
        }
    }

    /**
     * Provide a JSON Representation
     */
    @Override
    public String toString() {
        if (delegate == null)
            return "";

        return delegate.toString();
    }
}