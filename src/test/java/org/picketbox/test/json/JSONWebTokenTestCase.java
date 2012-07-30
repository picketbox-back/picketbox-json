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
 * Unit test the {@link JSONWebToken}
 *
 * @author anil saldhana
 * @since Jul 30, 2012
 */
public class JSONWebTokenTestCase {
    /**
     * Test the Plaintext JWT usecase
     *
     * @throws Exception
     */
    @Test
    public void testPlainTextJWT() throws Exception {
        String token = "eyJhbGciOiJub25lIn0=.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ==.";
        JSONWebToken jwt = new JSONWebToken();
        jwt.load(token);
        assertEquals("{\"alg\":\"none\"}", jwt.getHeader().toString());

        JSONObject data = jwt.getData();
        assertEquals("joe", data.getString("iss"));
        assertEquals("1300819380", data.getString("exp"));
        assertEquals("true", data.getString("http://example.com/is_root"));
    }

    @Test
    public void testJWTWithMAC() throws Exception {
        String header = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
        String text = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}";

        String token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
                + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ=="
                + ".ZXlKaGJHY2lPaUpJVXpJMU5pSjkuZXlKbGVIQWlPakV6TURBNE1Ua3pPREFzSW1oMGRIQTZMeTlsZUdGdGNHeGxMbU52Yl"
                + "M5cGMxOXliMjkwSWpwMGNuVmxMQ0pwYzNNaU9pSnFiMlVpZlE9PS5Zemt4T1RnM09USTNaRGc0T1dWa1kyRXdNV00wWWpneFl"
                + "qSTNOamhtWkRrM016QTJPREExWlRkallUSTNObU5pWTJJeFltUm1aRGsxWldOalltWXdZdz09";

        JSONWebToken jwt = new JSONWebToken();
        jwt.load(token);
        jwt.validate();

        JSONObject headerObj = new JSONObject(header);
        JSONObject textObj = new JSONObject(text);

        JSONObject jwtHeader = jwt.getHeader();
        JSONObject jwtData = jwt.getData();

        assertEquals(headerObj.getString("typ"), jwtHeader.getString("typ"));
        assertEquals(headerObj.getString("alg"), jwtHeader.getString("alg"));

        assertEquals(textObj.getString("iss"), jwtData.getString("iss"));
        assertEquals(textObj.getString("exp"), jwtData.getString("exp"));
    }
}