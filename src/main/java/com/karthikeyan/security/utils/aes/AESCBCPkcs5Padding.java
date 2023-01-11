package com.karthikeyan.security.utils.aes;

import com.karthikeyan.security.utils.Base64Utils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

@Slf4j
public class AESCBCPkcs5Padding implements AESUtils {

    @Override
    public String encrypt(String plaintext, String key) throws GeneralSecurityException {
        log.info("AES Encryption Processing");
        byte[] IV = Arrays.copyOf(key.getBytes(), 16);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), AES);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext.getBytes());
        log.info("AES Encryption Completed");
        return Base64Utils.encode(cipherText);
    }

    @Override
    public String decrypt(String cipherText, String key) throws GeneralSecurityException {
        log.info("AES Decryption Processing");
        cipherText = cipherText.replace("\\r", "");
        cipherText = cipherText.replace("\\n", "");
        byte[] IV = Arrays.copyOf(key.getBytes(), 16);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), AES);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decryptedText = cipher.doFinal(Base64Utils.decode(cipherText));
        log.info("AES Decryption Completed");
        return new String(decryptedText);
    }

}
