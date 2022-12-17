package com.example.authserver.common;

import com.example.authserver.common.jwtUtils.Payload;
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.gson.io.GsonSerializer;
import io.jsonwebtoken.impl.compression.GzipCompressionCodec;
import io.jsonwebtoken.impl.crypto.DefaultJwtSigner;
import io.jsonwebtoken.impl.crypto.JwtSigner;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.example.authserver.common.jwtUtils.Variables.*;

public class DefaultJwtBuilder {
    private Map<String, String> header;
    private Payload payload;

    private Key key;
    private SignatureAlgorithm algorithm;
    private Serializer<Map<String,?>> serializer;
    private Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
    private CompressionCodec compressionCodec;

    public DefaultJwtBuilder(String type) {
        this.header = new HashMap<>();
        this.payload = new Payload();
        this.key = type.equals("accessToken") ? accessTokenKey : refreshTokenKey;
        this.algorithm = SignatureAlgorithm.forSigningKey(key);
        this.serializer = new GsonSerializer<>();
        this.compressionCodec = new GzipCompressionCodec();
    }

    public DefaultJwtBuilder setHeader(String name, String value) {
        header.put(name, value);
        return this;
    }

    public DefaultJwtBuilder setPayload(String name, String value, String type) {
        switch (type) {
            case "registered" -> payload.getRegisteredClaims().put(name, value);
            case "public" -> payload.getPublicClaims().put(name, value);
            case "private" -> payload.getPrivateClaims().put(name, value);
        }
        return this;
    }

    public String compact() {
        String jwt = "";

        String base64UrlEncodedHeader = base64UrlEncoder.encode(serializer.serialize(header));

        jwt += base64UrlEncodedHeader + ".";

        HashMap<String, String> totalPayload = new HashMap<>(payload.getRegisteredClaims());
        totalPayload.putAll(payload.getPrivateClaims());
        totalPayload.putAll(payload.getPublicClaims());

        byte[] bytes = serializer.serialize(totalPayload);

        jwt += base64UrlEncoder.encode(compressionCodec.compress(bytes));
        byte[] bytes1 = jwt.getBytes(StandardCharsets.US_ASCII);

        JwtSigner signer = createSigner(algorithm, key);
        String base64UrlSignature = signer.sign(jwt);
        jwt += "." + base64UrlSignature;

        return jwt;
    }

    protected JwtSigner createSigner(SignatureAlgorithm alg, Key key) {
        return new DefaultJwtSigner(alg, key, base64UrlEncoder);
    }
}
