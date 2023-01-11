package com.karthikeyan.security.utils.aes;

import com.karthikeyan.security.utils.Base64Utils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

import static com.karthikeyan.security.utils.Base64Utils.encode;

@Slf4j
public class AESECBPkcs7Padding implements AESUtils {


    private Cipher cipher;

    public AESECBPkcs7Padding() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Security.getProvider(BC);
        cipher = Cipher.getInstance(AES_BC_ECB_PKCS7, BC);

    }

    public String encrypt(String plaintext, String key) throws GeneralSecurityException {
        byte[] orig = plaintext.getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), AES));
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
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), AES));
        byte[] encrypted = Base64Utils.decode(cipherText);
        byte[] plainText = new byte[cipher.getOutputSize(encrypted.length)];
        int ptLength = cipher.update(encrypted, 0, encrypted.length, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        return new String(Arrays.copyOfRange(plainText, 0, ptLength));
    }


}
