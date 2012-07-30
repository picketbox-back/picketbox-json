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
package org.picketbox.json;

/**
 * Define constants
 *
 * @author anil saldhana
 * @since Jul 24, 2012
 */
public interface PicketBoxJSONConstants {

    String EC = "EC";
    String EXP = "exp";
    String MOD = "mod";
    String KEYS = "keys";
    String KID = "kid";
    String RSA = "RSA";
    String RSA_SHA_256 = "RS256";
    String SIG = "sig";

    interface COMMON {
        String ALG = "alg";
        String ENC = "enc";
        String HMAC_SHA_256 = "HS256";
        String PERIOD = ".";
    }

    interface JWS {
        String SIGN_ALG_HS256 = "HS256";
        String SIGN_ALG_HS384 = "HS384";
        String SIGN_ALG_HS512 = "HS512";

        String SIGN_ALG_ES256 = "ES256";
        String SIGN_ALG_ES383 = "ES384";
        String SIGN_ALG_ES512 = "ES512";

        String SIGN_ALG_RS256 = "RS256";
        String SIGN_ALG_RS383 = "RS384";
        String SIGN_ALG_RS512 = "RS512";
    }

    interface JWE {
        String AES = "AES";
        String AES_CBC_128 = "A128CBC";
        String AES_GCM_256 = "A256GCM";
        String INTEGRITY = "int";
        String IV = "iv";

        String ENC_ALG_RSA1_5 = "RSA1_5";
        String ENC_ALG_RSA_OAEP = "RSA-OAEP";
        String ENC_ALG_ECDH_ES = "ECDH-ES";
        String ENC_ALG_A128KW = "A128KW";
        String ENC_ALG_A256KW = "A256KW";

        String ENC_ALG_A128CBC = "A128CBC";
        String ENC_ALG_A192CBC = "A192CBC";
        String ENC_ALG_A256CBC = "A256CBC";
        String ENC_ALG_A512CBC = "A512CBC";
        String ENC_ALG_A128GCM = "A128GCM";
        String ENC_ALG_A192GCM = "A192GCM";
        String ENC_ALG_A256GCM = "A256GCM";
        String ENC_ALG_A512GCM = "A512GCM";
    }
}