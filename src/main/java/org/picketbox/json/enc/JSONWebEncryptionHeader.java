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
import static org.picketbox.json.PicketBoxJSONConstants.JWS.SIGN_ALG_HS256;
import static org.picketbox.json.PicketBoxJSONConstants.JWS.SIGN_ALG_HS384;
import static org.picketbox.json.PicketBoxJSONConstants.JWS.SIGN_ALG_HS512;
import static org.picketbox.json.PicketBoxJSONConstants.JWE.ENC_ALG_A128CBC;
import static org.picketbox.json.PicketBoxJSONConstants.JWE.ENC_ALG_A192CBC;
import static org.picketbox.json.PicketBoxJSONConstants.JWE.ENC_ALG_A256CBC;
import static org.picketbox.json.PicketBoxJSONConstants.JWE.ENC_ALG_A512CBC;
import static org.picketbox.json.PicketBoxJSONConstants.JWE.IV;
import static org.picketbox.json.PicketBoxJSONConstants.JWE.INTEGRITY;

import java.io.StringReader;

import javax.crypto.Cipher;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.picketbox.core.PicketBoxMessages;
import org.picketbox.core.exceptions.ProcessingException;
import org.picketbox.core.json.PicketBoxJSONConstants;
import org.picketbox.json.PicketBoxJSONMessages;

/**
 * Represents the JSONWebEncryptionHeader
 *
 * @author anil saldhana
 * @since Jul 27, 2012
 */
public class JSONWebEncryptionHeader {
    private String alg;
    private String enc;
    private String integrity;
    private String kdf;
    private String iv;
    private String epk;
    private String zip;
    private String jku;
    private String jwk;
    private String x5u;
    private String x5t;
    private String x5c;
    private String kid;
    private String typ;
    private String cty;

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getEnc() {
        return enc;
    }

    public void setEnc(String enc) {
        this.enc = enc;
    }

    public String getIntegrity() {
        return integrity;
    }

    public void setIntegrity(String integrity) {
        this.integrity = integrity;
    }

    public String getKdf() {
        return kdf;
    }

    public void setKdf(String kdf) {
        this.kdf = kdf;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getEpk() {
        return epk;
    }

    public void setEpk(String epk) {
        this.epk = epk;
    }

    public String getZip() {
        return zip;
    }

    public void setZip(String zip) {
        this.zip = zip;
    }

    public String getJku() {
        return jku;
    }

    public void setJku(String jku) {
        this.jku = jku;
    }

    public String getJwk() {
        return jwk;
    }

    public void setJwk(String jwk) {
        this.jwk = jwk;
    }

    public String getX5u() {
        return x5u;
    }

    public void setX5u(String x5u) {
        this.x5u = x5u;
    }

    public String getX5t() {
        return x5t;
    }

    public void setX5t(String x5t) {
        this.x5t = x5t;
    }

    public String getX5c() {
        return x5c;
    }

    public void setX5c(String x5c) {
        this.x5c = x5c;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getTyp() {
        return typ;
    }

    public void setTyp(String typ) {
        this.typ = typ;
    }

    public String getCty() {
        return cty;
    }

    public void setCty(String cty) {
        this.cty = cty;
    }

    public boolean needIntegrity() {
        return integrity != null;
    }

    public Cipher getCipherBasedOnAlg() throws ProcessingException {
        if (PicketBoxJSONConstants.JWE.RSAES_OAEP.equals(alg)) {
            try {
                return Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            } catch (Exception e) {
                throw PicketBoxMessages.MESSAGES.processingException(e);
            }
        } else if (PicketBoxJSONConstants.JWE.RSAES_PKCS1_V1_5.equals(alg)) {
            try {
                return Cipher.getInstance("RSA/ECB/PKCS1Padding");
            } catch (Exception e) {
                throw PicketBoxMessages.MESSAGES.processingException(e);
            }
        }
        return null;
    }

    public Cipher getCipherBasedOnEnc() throws ProcessingException {
        if (enc.contains("CBC")) {
            try {
                return Cipher.getInstance("AES/CBC/PKCS5Padding");
            } catch (Exception e) {
                throw PicketBoxMessages.MESSAGES.processingException(e);
            }
        }
        return null;
    }

    public int getCEKLength() {
        int cekLength = 0;
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

    public int getCIKLength() {
        int cikLength = 0;
        if (SIGN_ALG_HS256.equals(integrity)) {
            cikLength = 256 / 8;
        } else if (SIGN_ALG_HS384.equals(integrity)) {
            cikLength = 384 / 8;
        } else if (SIGN_ALG_HS512.equals(integrity)) {
            cikLength = 512 / 8;
        }
        return cikLength;
    }

    public String getMessageAuthenticationCode() {
        String algo = null;

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
            JSONTokener tokener = new JSONTokener(new StringReader(json));
            JSONObject header = new JSONObject(tokener);
            this.alg = header.getString(ALG);
            if (header.has(IV)) {
                this.iv = header.getString(IV);
            }
            if (header.has(INTEGRITY)) {
                this.integrity = header.getString(INTEGRITY);
            }
            if (header.has(ENC)) {
                this.enc = header.getString(ENC);
            }
        } catch (JSONException j) {
            throw PicketBoxMessages.MESSAGES.processingException(j);
        }
    }

    /**
     * Provide a JSON Representation
     */
    @Override
    public String toString() {
        JSONObject json = new JSONObject();
        try {
            if (alg != null) {
                json.put(PicketBoxJSONConstants.COMMON.ALG, alg);
            }
            if (enc != null) {
                json.put(PicketBoxJSONConstants.COMMON.ENC, enc);
            }
            if (iv != null) {
                json.put(PicketBoxJSONConstants.JWE.IV, iv);
            }
            if (integrity != null) {
                json.put(PicketBoxJSONConstants.JWE.INTEGRITY, integrity);
            }
        } catch (JSONException e) {
            throw PicketBoxJSONMessages.MESSAGES.jsonSerializationFailed(e);
        }
        return json.toString();
    }
}