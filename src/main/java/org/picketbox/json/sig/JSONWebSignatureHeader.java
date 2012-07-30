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

import static org.picketbox.json.PicketBoxJSONConstants.COMMON.ALG;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Represents a header
 *
 * @author anil saldhana
 * @since Jul 30, 2012
 */
public class JSONWebSignatureHeader {
    protected String alg;

    public JSONWebSignatureHeader(String alg) {
        this.alg = alg;
    }

    /**
     * Get the Algorithm
     *
     * @return
     */
    public String getAlg() {
        return alg;
    }

    /**
     * Get a {@link JSONObject} representation
     *
     * @return
     * @throws JSONException
     */
    public JSONObject get() throws JSONException {
        JSONObject json = new JSONObject();
        json.put(ALG, alg);
        return json;
    }

    /**
     * Given a {@link JSONObject}, obtain {@link JSONWebSignatureHeader}
     *
     * @param json
     * @return
     * @throws JSONException
     */
    public static JSONWebSignatureHeader create(JSONObject json) throws JSONException {
        return new JSONWebSignatureHeader(json.getString(ALG));
    }

    /**
     * Given a JSON String representing the header, obtain {@link JSONWebSignatureHeader}
     *
     * @param json
     * @return
     * @throws JSONExcption
     */
    public static JSONWebSignatureHeader create(String json) throws JSONException {
        JSONObject jsonObject = new JSONObject(json);
        return create(jsonObject);
    }
}