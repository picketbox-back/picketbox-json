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
package org.picketbox.test.json;

import static org.junit.Assert.assertEquals;

import org.json.JSONObject;
import org.junit.Test;
import org.picketbox.json.token.JSONWebToken;

/**
 * Unit test the API for JWT
 *
 * @author anil saldhana
 * @since Jul 31, 2012
 */
public class JSONWebTokenAPITestCase {

    /**
     * Test the JWT API for Plain Text usecase
     *
     * @throws Exception
     */
    @Test
    public void testPlainTextJWTAPI() throws Exception {
        String plainText = "{\"data\":\"Welcome to the world of AES\"}";

        JSONWebToken jwt = new JSONWebToken();
        jwt.setData(new JSONObject(plainText));

        // Let us create the header
        JSONObject header = new JSONObject();
        header.put("alg", "none");

        jwt.setHeader(header);

        String encodedJWT = jwt.encode();
        System.out.println(encodedJWT);

        // Let us decode
        jwt = new JSONWebToken();
        jwt.load(encodedJWT);

        assertEquals(plainText, jwt.getData().toString());
    }

    /**
     * Test the JWT API for signature use case
     *
     * @throws Exception
     */
    @Test
    public void testJWSAPI() throws Exception {
        String headerStr = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
        String text = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}";

        JSONWebToken jwt = new JSONWebToken();
        jwt.setData(new JSONObject(text));

        // Let us create the header
        JSONObject header = new JSONObject(headerStr);
        jwt.setHeader(header);

        String encodedJWT = jwt.encode();
        System.out.println(encodedJWT);

        // Let us decode
        jwt = new JSONWebToken();
        jwt.load(encodedJWT);

        assertEquals("joe", jwt.getData().getString("iss"));
    }
}