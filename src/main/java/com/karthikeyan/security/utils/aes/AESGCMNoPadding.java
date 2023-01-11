package com.karthikeyan.security.utils.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

public class AESGCMNoPadding implements AESUtils {

    public static final int GCM_TAG_LENGTH = 16;
    public static final int GCM_IV_LENGTH = 12;


    public String decrypt(String cipherText, String key) throws GeneralSecurityException {
        byte[] parts = Base64.getDecoder().decode(cipherText);
        byte[] ivBase64 = Arrays.copyOfRange(parts, 0, GCM_IV_LENGTH);
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), AES);
        Cipher cipher = Cipher.getInstance(AES_GCM_No);
        GCMParameterSpec params = new GCMParameterSpec(128, ivBase64, 0, ivBase64.length);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, params);
        byte[] decipheredText = cipher.doFinal(Arrays.copyOfRange(parts, GCM_IV_LENGTH, parts.length));
        return new String(decipheredText);
    }

    public String encrypt(String data, String key) throws GeneralSecurityException, IOException {
        byte[] IV = Arrays.copyOfRange(key.getBytes(), 0, GCM_IV_LENGTH);
        byte[] plaintext = data.getBytes();
        Cipher cipher = Cipher.getInstance(AES_GCM_No);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), AES);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(plaintext);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(IV);
        outputStream.write(cipherText);
        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
    }


    /*public String getAESKey() {
        int length = GCM_TAG_LENGTH;
        byte[] array = new byte[256];
        new Random().nextBytes(array);

        String randomString = new String(array, Charset.forName("UTF-8"));

        StringBuffer r = new StringBuffer();

        for (int k = 0; k < randomString.length(); k++) {

            char ch = randomString.charAt(k);

            if (((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) && (length > 0)) {

                r.append(ch);
                length--;
            }
        }
        return r.toString();
    }*/
}