package com.karthikeyan.security.utils;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Slf4j
@UtilityClass
public class PasswordUtil {

    public static String generatePassword(String stringToHash) {
        log.info("Creating PassWord Hash");
        MessageDigest digest = null;
        String sha256hex = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            byte[] byteData2 = digest.digest(stringToHash.getBytes(StandardCharsets.UTF_8));
            sha256hex = new String(Hex.encode(byteData2));
        } catch (NoSuchAlgorithmException e) {
            log.info("No Such Algorithm Excpetion");
            log.error("Error ", e);
        }
        return sha256hex;
    }

}
