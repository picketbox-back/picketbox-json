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

import java.io.IOException;

import org.jboss.logging.Cause;
import org.jboss.logging.Message;
import org.jboss.logging.MessageBundle;
import org.jboss.logging.Messages;
import org.picketbox.json.exceptions.ProcessingException;

/**
 * An instance of {@link MessageBundle} from JBoss Logging
 *
 * @author Stefan Guilhen
 * @since Jul 10, 2012
 */
@MessageBundle(projectCode = "PBOXJSON")
public interface PicketBoxJSONMessages {

    PicketBoxJSONMessages MESSAGES = Messages.getBundle(PicketBoxJSONMessages.class);

    @Message(id = 1, value = "keydatalen should be a multiple of 8")
    IllegalArgumentException keyDataLenError();

    @Message(id = 2, value = "keydatalen is larger than Maximum Value allowed by Unsigned Integer data type.")
    IllegalArgumentException keyDataLenLarge();

    @Message(id = 3, value = "The argument %s cannot be null")
    IllegalArgumentException invalidNullArgument(String argName);

    @Message(id = 4, value = "Hash Length is too large")
    RuntimeException hashLengthTooLarge();

    @Message(id = 5, value = "No such algorithm.")
    ProcessingException noSuchAlgorithm(@Cause Throwable throwable);

    @Message(id = 6, value = "Processing Exception.")
    ProcessingException processingException(@Cause Throwable throwable);

    @Message(id = 7, value = "JSON Web Signature Validation Failed.")
    ProcessingException jsonWebSignatureValidationFailed();

    @Message(id = 8, value = "JSON Serialization Failed.")
    RuntimeException jsonSerializationFailed(@Cause Throwable e);

    @Message(id = 9, value = "JSON Encryption Header Missing.")
    IllegalStateException jsonEncryptionHeaderMissing();

    @Message(id = 10, value = "Invalid Base64 character found: %s")
    RuntimeException invalidBase64CharacterMessage(byte character);

    @Message(id = 11, value = "Error reading Base64 stream: nothing to read")
    IOException errorReadingBase64Stream();

    @Message(id = 12, value = "Error decoding from file %s")
    IllegalStateException errorDecodingFromFile(String fileName, @Cause Throwable throwable);

    @Message(id = 13, value = "Error decoding from file %s: file is too big (%s bytes)")
    IllegalStateException errorDecodingFromBigInputFile(String fileName, long fileSize);

    @Message(id = 14, value = "JSON Web Keys Missing.")
    RuntimeException jsonWebKeysMissing();

    @Message(id = 15, value = "Wrong Type of JSON Key.")
    RuntimeException wrongJsonKey();

    @Message(id = 16, value = "Error encoding from file %s")
    IllegalStateException errorEncodingFromFile(String fileName, @Cause Throwable throwable);

    @Message(id = 17, value = "Base64 input not properly padded")
    IOException invalidBase64Padding();
}