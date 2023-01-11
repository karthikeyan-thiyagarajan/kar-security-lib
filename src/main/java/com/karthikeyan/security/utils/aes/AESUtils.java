package com.karthikeyan.security.utils.aes;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * @author Karthikeyan on 11-01-2023
 */

public interface AESUtils {

    int KEY_SIZE_128 = 128;
    int KEY_SIZE_192 = 192;
    int KEY_SIZE_256 = 256;


    String AES = "AES";
    String BC = "BC";

    String AES_ECB_PKCS5 = "AES/ECB/PKCS5Padding";
    String AES_ECB_NO = "AES/ECB/NoPadding";

    String AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";
    String AES_CBC_NO = "AES/CBC/NoPadding";

    String AES_GCM_No = "AES/GCM/NoPadding";
    String AES_BC_ECB_PKCS7 = "AES/ECB/PKCS7Padding";

    String AES_CFB_PKCS5 = "AES/CFB/PKCS5Padding";
    String AES_OFB_PKCS5 = "AES/OFB/PKCS5Padding";

    static SecretKey generateKey(int keyLength) throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keyLength);
        return keyGenerator.generateKey();
    }

    String encrypt(String plaintext, String key) throws GeneralSecurityException, IOException;

    String decrypt(String cipherText, String key) throws GeneralSecurityException;
}
