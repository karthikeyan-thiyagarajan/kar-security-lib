package com.karthikeyan.security.utils.aes;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

@Slf4j
public class AESECBPkcs7Padding implements AESUtils {


    private Cipher cipher;

    public AESECBPkcs7Padding() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Security.getProvider("BC");
        cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

    }

    public String encrypt(String plaintext, String key) throws GeneralSecurityException {
        byte[] orig = plaintext.getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
        byte[] cipherText = new byte[cipher.getOutputSize(orig.length)];
        int ctLength = cipher.update(orig, 0, orig.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        String encoded;
        try {
            encoded = encode(Arrays.copyOfRange(cipherText, 0, ctLength));
        } catch (Exception e) {
            log.error("Error While Encrypting Esign Request ");
            log.error("Error Message {} ", e.getMessage());

            encoded = "";
        }
        return encoded;
    }

    public String decrypt(String cipherText, String key) throws GeneralSecurityException {
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
        byte[] encrypted = decode(cipherText);
        byte[] plainText = new byte[cipher.getOutputSize(encrypted.length)];
        int ptLength = cipher.update(encrypted, 0, encrypted.length, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        return new String(Arrays.copyOfRange(plainText, 0, ptLength));
    }

    private String encode(byte[] bytes) {
        byte[] encoded = Base64.getEncoder().encode(bytes);
        return new String(encoded);
    }

    private byte[] decode(String str) {
        byte[] encoded = str.getBytes();
        return Base64.getDecoder().decode(encoded);
    }
}
