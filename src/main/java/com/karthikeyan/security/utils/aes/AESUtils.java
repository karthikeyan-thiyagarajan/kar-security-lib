package com.karthikeyan.security.utils.aes;

import java.security.GeneralSecurityException;

/**
 * @author Karthikeyan on 11-01-2023
 */

public interface AESUtils {

    String encrypt(String plaintext, String key) throws GeneralSecurityException;

    String decrypt(String cipherText, String key) throws GeneralSecurityException;
}
