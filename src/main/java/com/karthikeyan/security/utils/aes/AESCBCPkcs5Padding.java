package com.karthikeyan.security.utils.aes;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Random;

@Slf4j
public class AESCBCPkcs5Padding implements AESUtils {

    public static final String AES_ALGORITHM = "AES";
    public static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    public static final int ENC_BITS = 256;
    public static final int KEY_SIZE = 32;
    private static KeyGenerator KEYGEN;
    private static Cipher ENCRYPT_CIPHER;
    private static Cipher DECRYPT_CIPHER;

    static {
        try {
            ENCRYPT_CIPHER = Cipher.getInstance(AES_TRANSFORMATION);
            DECRYPT_CIPHER = Cipher.getInstance(AES_TRANSFORMATION);
            KEYGEN = KeyGenerator.getInstance(AES_ALGORITHM);
            KEYGEN.init(ENC_BITS);
        } catch (Exception e) {
            log.error("Error :" + e);
        }
    }

    @Override
    public String encrypt(String plaintext, String key) throws GeneralSecurityException {
        log.info("AES Encryption Processing");
        byte[] IV = new byte[16];

        // Copy 16 bits from key
        IV = Arrays.copyOf(key.getBytes(), 16);

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);

        // Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        // Initialize Cipher for ENCRYPT_MODE
        ENCRYPT_CIPHER.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        // Perform Encryption
        byte[] cipherText = ENCRYPT_CIPHER.doFinal(plaintext.getBytes());
        log.info("AES Encryption Completed");
        return new String(Base64.encode(cipherText));
    }

    @Override
    public String decrypt(String cipherText, String key) throws GeneralSecurityException {
        log.info("AES Decryption Processing");
        cipherText = cipherText.replace("\\r", "");
        cipherText = cipherText.replace("\\n", "");

        byte[] IV = new byte[16];

        // Copy 16 bits from key
        IV = Arrays.copyOf(key.getBytes(), 16);

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);

        // Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        // Initialize Cipher for DECRYPT_MODE
        DECRYPT_CIPHER.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        // Perform Decryption
        byte[] decryptedText = DECRYPT_CIPHER.doFinal(Base64.decode(cipherText));

        log.info("AES Decryption Completed");
        return new String(decryptedText);
    }

    public String getAESKey() {
        int length = KEY_SIZE;
        byte[] array = new byte[256];
        new Random().nextBytes(array);

        String randomString = new String(array, StandardCharsets.UTF_8);

        StringBuffer r = new StringBuffer();

        for (int k = 0; k < randomString.length(); k++) {

            char ch = randomString.charAt(k);

            if (((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) && (length > 0)) {

                r.append(ch);
                length--;
            }
        }
        return r.toString();
    }


}
