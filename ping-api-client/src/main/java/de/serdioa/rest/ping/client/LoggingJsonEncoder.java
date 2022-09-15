package de.serdioa.rest.ping.client;

import java.util.Map;
import java.util.function.Consumer;

import org.springframework.core.ResolvableType;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import org.springframework.util.MimeType;


public class LoggingJsonEncoder extends Jackson2JsonEncoder {

    private final Consumer<byte[]> payloadConsumer;


    public LoggingJsonEncoder(final Consumer<byte[]> payloadConsumer) {
        this.payloadConsumer = payloadConsumer;
    }


    @Override
    public DataBuffer encodeValue(final Object value, final DataBufferFactory bufferFactory,
            final ResolvableType valueType, final MimeType mimeType, final Map<String, Object> hints) {

        // Encode/Serialize data to JSON
        final DataBuffer data = super.encodeValue(value, bufferFactory, valueType, mimeType, hints);

        // Interception: Generate Signature and inject header into request
        payloadConsumer.accept(ByteUtils.extractBytesAndReset(data));

        // Return the data as normal
        return data;
    }
}
