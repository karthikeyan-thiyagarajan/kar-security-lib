package com.karthikeyan.security.utils;

import lombok.experimental.UtilityClass;
import org.apache.commons.io.IOUtils;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

@UtilityClass
public class FileIOUtils {

    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(FileIOUtils.class);

    private static ClassLoader classLoader;

    public static String getFileContentAsString(String fileName) {
        String fileAsString = null;
        try {
            classLoader = FileIOUtils.class.getClassLoader();
            fileAsString = IOUtils.toString(classLoader.getResourceAsStream(fileName), StandardCharsets.UTF_8);
        } catch (IOException e) {
            LOGGER.info("IO Excpetion Occured");
            LOGGER.error("Error ", e);
        }
        return fileAsString;
    }

    public static String getFileContent(String fileName) throws IOException {
        return new String(Files.readAllBytes(Paths.get(fileName)));
    }

    public static InputStream getFileContentAsStream(String fileName) {
        try {
            classLoader = FileIOUtils.class.getClassLoader();
            return classLoader.getResourceAsStream(fileName);
        } catch (Exception e) {
            LOGGER.info("IO Excpetion Occured");
            LOGGER.error("Error ", e);
        }
        return null;
    }
}