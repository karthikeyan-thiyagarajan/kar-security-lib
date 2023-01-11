package com.karthikeyan.security.utils;

import lombok.experimental.UtilityClass;

import java.util.Base64;

/**
 * @author Karthikeyan on 11-01-2023
 */


@UtilityClass
public class Base64Utils {

    public static String encode(byte[] bytes) {
        byte[] encoded = Base64.getEncoder().encode(bytes);
        return new String(encoded);
    }

    public static byte[] decode(String str) {
        byte[] encoded = str.getBytes();
        return Base64.getDecoder().decode(encoded);
    }
}
