package com.example.resourceserver.common;

import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.gson.io.GsonDeserializer;
import io.jsonwebtoken.impl.compression.GzipCompressionCodec;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Deserializer;

import java.util.Map;

public class DefaultJwtParser {
    private Decoder<String, byte[]> decoder;
    private CompressionCodec compressionCodec;
    private Deserializer<Map<String, ?>> deserializer;

    public DefaultJwtParser() {
        this.decoder = Decoders.BASE64URL;
        this.compressionCodec = new GzipCompressionCodec();
        this.deserializer = new GsonDeserializer<>();
    }

    public Map<String, ?> getHeader(String token) {
        String header = token.split("[.]")[0];
        return deserializer.deserialize(decoder.decode(header));
    }

    public Map<String, ?> getBody(String token) {
        String payload = token.split("[.]")[1];

        byte[] bytes = decoder.decode(payload);
        byte[] decompress = compressionCodec.decompress(bytes);
        return deserializer.deserialize(decompress);
    }
}
