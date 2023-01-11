package com.karthikeyan.security.utils.aes;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class AESGCMNoPadding {

    public static final int GCM_TAG_LENGTH = 16;
    public static final int GCM_IV_LENGTH = 12;
    private static byte[] ivBase64;

    public static String encrypt(String data, String key) throws Exception {
        byte[] IV = Arrays.copyOfRange(key.getBytes(), 0, GCM_IV_LENGTH);
        byte[] plaintext = data.getBytes();
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");

        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(IV);
        outputStream.write(cipherText);

        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
    }

    public static String decrypt(String cipherText, String masterkey)
            throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] parts = Base64.getDecoder().decode(cipherText);
        ivBase64 = Arrays.copyOfRange(parts, 0, GCM_IV_LENGTH);
        System.out.println("master key" + masterkey);
        SecretKeySpec skeySpec = new SecretKeySpec(masterkey.getBytes("UTF-8"), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        String text = new String();
        GCMParameterSpec params = new GCMParameterSpec(128, ivBase64, 0, ivBase64.length);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, params);
        byte[] decipheredText = cipher.doFinal(Arrays.copyOfRange(parts, GCM_IV_LENGTH, parts.length));
        return new String(decipheredText);
    }

    public String getAESKey() {
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
    }
}