package com.karthikeyan.security.utils.rsa;

import org.bouncycastle.util.encoders.Base64;
import com.karthikeyan.security.utils.FileIOUtils;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class RSAGCMNoPadding implements RSAUtils {

    private static String getKey(String filename) {
        return FileIOUtils.getFileContentAsString(filename);
    }

    public static RSAPrivateKey getPrivateKey(String filename) throws GeneralSecurityException {
        String privateKeyPEM = getKey(filename);
        return getPrivateKeyFromString(privateKeyPEM);
    }

    public static RSAPrivateKey getPrivateKeyFromString(String key) throws GeneralSecurityException {
        String privateKeyPEM = key;
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.decode(privateKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) kf.generatePrivate(keySpec);
    }

    public String decrypt(String cipherText, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.decode(cipherText)), StandardCharsets.UTF_8);
    }

    private PublicKey readPublicKey() throws GeneralSecurityException {
        InputStream inputStream = FileIOUtils.getFileContentAsStream("desk_nine_cert.pem");
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) f.generateCertificate(inputStream);
        return certificate.getPublicKey();
    }

    public String encrypt(String plaintext,PublicKey publicKey) throws GeneralSecurityException {
//        PublicKey key = this.readPublicKey();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedByte = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.encode(encryptedByte));
    }

}
