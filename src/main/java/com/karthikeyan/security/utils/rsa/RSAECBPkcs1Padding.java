package com.karthikeyan.security.utils.rsa;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class RSAECBPkcs1Padding implements RSAUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(RSAUtils.class);

    private final String mode = "dev";

    public static PublicKey getPublicKey(InputStream inputStream) throws GeneralSecurityException {
        LOGGER.info("Generating Public Key For RSA");
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) f.generateCertificate(inputStream);
        PublicKey pk = certificate.getPublicKey();
        LOGGER.info("Public Key Generation Completed");
        return pk;
    }

    private PublicKey readPublicKey(String fileName) throws GeneralSecurityException {
        LOGGER.info("Generating Public Key For RSA");
        InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(fileName);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) f.generateCertificate(inputStream);
        PublicKey pk = certificate.getPublicKey();
        LOGGER.info("Public Key Generation Completed");
        return pk;

    }

    @Override
    public String encrypt(String plaintext, PublicKey publicKey) throws GeneralSecurityException {
        LOGGER.info("RSA Encryption Processing");
//        PublicKey key = this.readPublicKey(type);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedByte = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        LOGGER.info("RSA Encryption Completed");
        return new String(Base64.encode(encryptedByte));
    }

    @Override
    public String decrypt(String cipherText, PrivateKey privateKey) {
        return null;
    }
}
