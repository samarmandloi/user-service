package com.pm.userservice.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;

@Configuration
public class JwtConfig {

    @Bean
    public JwtEncoder jwtEncoder(
            @Value("${jwt.private-key-path}") String privateKeyPath)
            throws Exception {

        Path privatePath = Path.of(privateKeyPath);
        Path publicPath = privatePath.resolveSibling("public.pem");

        RSAPrivateKey privateKey = loadPrivateKey(privatePath);
        RSAPublicKey publicKey = loadPublicKey(publicPath);

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID("user-service-key")
                .build();

        JWKSource<SecurityContext> jwkSource =
                new ImmutableJWKSet<>(new JWKSet(rsaKey));

        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(
            @Value("${jwt.private-key-path}") String privateKeyPath)
            throws Exception {

        Path publicPath = Path.of(privateKeyPath)
                .resolveSibling("public.pem");

        RSAPublicKey publicKey = loadPublicKey(publicPath);

        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();

        decoder.setJwtValidator(
                JwtValidators.createDefaultWithIssuer("user-service")
        );
        return decoder;
    }

    private RSAPrivateKey loadPrivateKey(Path path) throws Exception {
        String pem = Files.readString(path, StandardCharsets.UTF_8);
        String content = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(content);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                .generatePrivate(keySpec);
    }

    private RSAPublicKey loadPublicKey(Path path) throws Exception {
        String pem = Files.readString(path, StandardCharsets.UTF_8);
        String content = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(content);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(keySpec);
    }
}
