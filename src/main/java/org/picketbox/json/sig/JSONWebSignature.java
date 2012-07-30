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
package org.picketbox.json.sig;

import static org.picketbox.json.PicketBoxJSONConstants.COMMON.HMAC_SHA_256;
import static org.picketbox.json.PicketBoxJSONConstants.COMMON.PERIOD;

import java.io.UnsupportedEncodingException;

import org.json.JSONException;
import org.json.JSONObject;
import org.picketbox.json.PicketBoxJSONMessages;
import org.picketbox.json.exceptions.ProcessingException;
import org.picketbox.json.util.Base64;
import org.picketbox.json.util.HmacSha256Util;
import org.picketbox.json.util.PicketBoxJSONUtil;

/**
 * Represents a JSON Web Signature
 *
 * @author anil saldhana
 * @since Jul 24, 2012
 */
public class JSONWebSignature {
    protected JSONObject payload;
    protected JSONWebSignatureHeader header;

    /**
     * Get the JSON Payload
     *
     * @return
     */
    public JSONObject getPayload() {
        return payload;
    }

    /**
     * Set the Payload
     *
     * @param payload
     */
    public void setPayload(JSONObject payload) {
        this.payload = payload;
    }

    /**
     * Set the Payload
     *
     * @param payload
     * @throws JSONException
     */
    public void setPayload(String pay) throws JSONException {
        this.payload = new JSONObject(pay);
    }

    /**
     * Get the JWS Header
     *
     * @return
     */
    public JSONWebSignatureHeader getHeader() {
        return header;
    }

    /**
     * Set the JWS Header
     *
     * @param header
     */
    public void setHeader(JSONWebSignatureHeader header) {
        this.header = header;
    }

    /**
     * Encode the Payload
     *
     * @return
     * @throws ProcessingException
     */
    public String encode() throws ProcessingException {
        if (header == null) {
            throw PicketBoxJSONMessages.MESSAGES.jsonWebSignatureHeaderMissing();
        }

        if (HMAC_SHA_256.equals(header.getAlg())) {
            return encodeUsingHmacSha26();
        }
        throw new RuntimeException();
    }

    /**
     * Encode the Payload
     *
     * @return
     * @throws ProcessingException
     */
    public static JSONWebSignature decode(String encoded) throws ProcessingException {
        String decodedOverall = null;
        try {
            decodedOverall = new String(Base64.decode(encoded), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }

        // Find the first period
        int index = decodedOverall.indexOf(PERIOD);

        String encodedHeader = decodedOverall.substring(0, index);
        String withoutEncodedHeader = decodedOverall.substring(index + 1);

        int secondPeriod = withoutEncodedHeader.indexOf(PERIOD);

        String encodedPayload = withoutEncodedHeader.substring(0, secondPeriod);

        String encodedSignature = withoutEncodedHeader.substring(secondPeriod + 1);

        String decodedSignature = null;

        try {
            decodedSignature = new String(Base64.decode(encodedSignature), "UTF-8");
        } catch (UnsupportedEncodingException e1) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e1);
        }

        // Validation
        String encodedValue = HmacSha256Util.encode(encodedHeader + PERIOD + encodedPayload);
        if (encodedValue.equals(decodedSignature) == false) {
            throw PicketBoxJSONMessages.MESSAGES.jsonWebSignatureValidationFailed();
        }
        JSONWebSignature sig = new JSONWebSignature();
        try {
            sig.setHeader(JSONWebSignatureHeader.create(new String(Base64.decode(encodedHeader), "UTF-8")));
            sig.setPayload(new String(Base64.decode(encodedPayload), "UTF-8"));
        } catch (Exception e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
        return sig;
    }

    /**
     * Encode using HmacSha256
     *
     * @return
     * @throws ProcessingException
     */
    protected String encodeUsingHmacSha26() throws ProcessingException {
        try {
            // Encode the header
            String base64EncodedHeader = PicketBoxJSONUtil.b64Encode(header.get().toString());

            // Encode the payload
            String base64EncodedPayload = PicketBoxJSONUtil.b64Encode(payload.toString());

            StringBuilder securedInput = new StringBuilder(base64EncodedHeader);
            securedInput.append(PERIOD).append(base64EncodedPayload);

            String sigValue = HmacSha256Util.encode(securedInput.toString());

            String encodedSig = PicketBoxJSONUtil.b64Encode(sigValue);

            StringBuilder result = new StringBuilder();
            result.append(base64EncodedHeader).append(PERIOD).append(base64EncodedPayload).append(PERIOD).append(encodedSig);
            return PicketBoxJSONUtil.b64Encode(result.toString());
        } catch (Exception e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }
}