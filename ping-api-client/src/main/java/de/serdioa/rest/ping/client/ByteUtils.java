package de.serdioa.rest.ping.client;

import org.springframework.core.io.buffer.DataBuffer;


public class ByteUtils {

    public static byte[] extractBytesAndReset(final DataBuffer data) {
        final byte[] bytes = new byte[data.readableByteCount()];
        data.read(bytes);
        data.readPosition(0);
        return bytes;
    }
}
