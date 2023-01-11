package com.karthikeyan.security.utils.rsa;


import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class QuickDefaultRSA implements RSAUtils {

    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    @Override
    public String encrypt(String message, PublicKey publicKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return new String(cipher.doFinal(message.getBytes()));
    }

    @Override
    public String decrypt(String cipherText, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(cipherText.getBytes(StandardCharsets.UTF_8)));
    }

}


