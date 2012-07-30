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
package org.picketbox.json.util;

import java.io.UnsupportedEncodingException;

import org.picketbox.json.PicketBoxJSONMessages;
import org.picketbox.json.exceptions.ProcessingException;

/**
 * Util class
 *
 * @author anil saldhana
 * @since Jul 30, 2012
 */
public class PicketBoxJSONUtil {

    /**
     * Base64 Encode without breaking lines
     *
     * @param str
     * @return
     * @throws ProcessingException
     */
    public static String b64Encode(String str) throws ProcessingException {
        try {
            return Base64.encodeBytes(str.getBytes("UTF-8"), Base64.DONT_BREAK_LINES);
        } catch (UnsupportedEncodingException e) {
            throw PicketBoxJSONMessages.MESSAGES.processingException(e);
        }
    }

    /**
     * Base64 Encode without breaking lines
     *
     * @param str
     * @return
     */
    public static String b64Encode(byte[] str) {
        return Base64.encodeBytes(str, Base64.DONT_BREAK_LINES);
    }
}