package com.example.authserver.common;

import io.jsonwebtoken.*;
import io.jsonwebtoken.gson.io.GsonDeserializer;
import io.jsonwebtoken.impl.compression.GzipCompressionCodec;
import io.jsonwebtoken.impl.crypto.*;
import io.jsonwebtoken.io.*;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Map;

import static com.example.authserver.common.jwtUtils.Variables.*;

public class DefaultJwtParser {
    private Decoder<String, byte[]> decoder;
    private Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
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

    public Map<String, ?> getPayload(String token) {
        String payload = token.split("[.]")[1];

        byte[] bytes = decoder.decode(payload);
        byte[] decompress = compressionCodec.decompress(bytes);
        return deserializer.deserialize(decompress);
    }

    public boolean isExpiredToken(String token) {
        LocalDateTime expireTime = LocalDateTime.parse((String)getPayload(token).get("exp"));
        return expireTime.isBefore(LocalDateTime.now());
    }

    public void validateToken(String token, String type) {
        Key key = type.equals("accessToken") ? accessTokenKey : refreshTokenKey;

        Map<String, ?> header = getHeader(token);
        Map<String, ?> payload = getPayload(token);

        SignatureAlgorithm algorithm = SignatureAlgorithm.forSigningKey(key);;

        JwtSignatureValidator validator;
        try {
            algorithm.assertValidVerificationKey(key); //since 0.10.0: https://github.com/jwtk/jjwt/issues/334
            validator = createSignatureValidator(algorithm, key);
        } catch (WeakKeyException e) {
            throw e;
        } catch (InvalidKeyException | IllegalArgumentException e) {
            String algName = algorithm.getValue();
            String msg = "The parsed JWT indicates it was signed with the '" + algName + "' signature " +
                    "algorithm, but the provided " + key.getClass().getName() + " key may " +
                    "not be used to verify " + algName + " signatures.  Because the specified " +
                    "key reflects a specific and expected algorithm, and the JWT does not reflect " +
                    "this algorithm, it is likely that the JWT was not expected and therefore should not be " +
                    "trusted.  Another possibility is that the parser was provided the incorrect " +
                    "signature verification key, but this cannot be assumed for security reasons.";
            throw new UnsupportedJwtException(msg, e);
        }

        String jwtWithoutSignature = token.split("[.]")[0] + "." + token.split("[.]")[1];
        String base64URLEncodedSignature = token.split("[.]")[2];

        if (!validator.isValid(jwtWithoutSignature, base64URLEncodedSignature)) {
            String msg = "JWT signature does not match locally computed signature. JWT validity cannot be " +
                    "asserted and should not be trusted.";
            throw new SignatureException(msg);
        }
    }

    protected JwtSignatureValidator createSignatureValidator(SignatureAlgorithm alg, Key key) {
        return new DefaultJwtSignatureValidator(alg, key, decoder);
    }
}
