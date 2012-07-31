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
package org.picketbox.json.token;

import java.security.PrivateKey;

import org.json.JSONException;
import org.json.JSONObject;
import org.picketbox.json.PicketBoxJSONConstants;
import org.picketbox.json.PicketBoxJSONMessages;
import org.picketbox.json.enc.JSONWebEncryption;
import org.picketbox.json.enc.JSONWebEncryptionHeader;
import org.picketbox.json.exceptions.ProcessingException;
import org.picketbox.json.sig.JSONWebSignature;
import org.picketbox.json.sig.JSONWebSignatureHeader;
import org.picketbox.json.util.Base64;
import org.picketbox.json.util.PicketBoxJSONUtil;

/**
 * Represents a JSON Web Token
 *
 * @author anil saldhana
 * @since Jul 30, 2012
 */
public class JSONWebToken {
    private JSONObject header;
    private JSONObject data;
    private String plainText = null;
    private String third = null;

    private PrivateKey privateKey;

    public String getPlainText() {
        return plainText;
    }

    /**
     * Get the header
     *
     * @return
     */
    public JSONObject getHeader() {
        return header;
    }

    /**
     * Get the data
     *
     * @return
     */
    public JSONObject getData() {
        return data;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Load the token from a formatted string
     *
     * @param tokenString
     * @throws ProcessingException
     */
    public void load(String tokenString) throws ProcessingException {
        String[] tokens = tokenString.split("\\.");
        String payload = null;

        int len = tokens.length;
        try {

            if (len > 4)
                throw PicketBoxJSONMessages.MESSAGES.invalidNumberOfTokens(tokens.length);
            String headerStr = new String(Base64.decode(tokens[0]));
            // Process the header
            header = new JSONObject(headerStr);

            if ("none".equals(header.getString(PicketBoxJSONConstants.COMMON.ALG))) {
                payload = new String(Base64.decode(tokens[1]));
                // Process the payload
                data = new JSONObject(payload);
                return;
            }

            // Process the header now
            if (header.has("enc")) {
                // JWE usecase

                JSONWebEncryption jsonWebEnc = new JSONWebEncryption();
                JSONWebEncryptionHeader encHeader = new JSONWebEncryptionHeader();
                encHeader.load(headerStr);
                jsonWebEnc.setJsonWebEncryptionHeader(encHeader);

                plainText = jsonWebEnc.decrypt(tokenString, privateKey);
                return;
            } else {
                String encodedString = PicketBoxJSONUtil.b64Encode(tokenString);
                // sig usecase
                JSONWebSignature jsonWebSignature = JSONWebSignature.decode(encodedString);
                header = jsonWebSignature.getHeader().get();
                data = jsonWebSignature.getPayload();
            }
        } catch (JSONException e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }

    /**
     * Validate the JWT
     *
     * @throws ProcessingException
     */
    public void validate() throws ProcessingException {
        try {
            String alg = header.getString(PicketBoxJSONConstants.COMMON.ALG);
            if ("none".equals(alg))
                return;

            if (PicketBoxJSONConstants.COMMON.HMAC_SHA_256.equals(alg)) {

                JSONWebSignature sig = new JSONWebSignature();
                JSONWebSignatureHeader sigHeader = JSONWebSignatureHeader.create(header.toString());
                sig.setHeader(sigHeader);
                sig.setPayload(data);

                String encodedSignature = sig.encode().trim();
                // Use the third variable
                if (encodedSignature.equals(third) == false) {
                    throw PicketBoxJSONMessages.MESSAGES.doesNotMatch("signatures");
                }
            }
        } catch (Exception e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }
}