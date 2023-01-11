package com.karthikeyan.security.utils.rsa;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author Karthikeyan on 11-01-2023
 */

public interface RSAUtils {

    String encrypt(String plaintext, PublicKey publicKey) throws GeneralSecurityException;

    String decrypt(String cipherText, PrivateKey privateKey) throws GeneralSecurityException;


}
