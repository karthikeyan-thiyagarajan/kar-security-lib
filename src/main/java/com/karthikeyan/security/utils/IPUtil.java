package com.karthikeyan.security.utils;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Karthikeyan Thiyagarajan
 * @version 1.0
 */

@Slf4j
@UtilityClass
public class IPUtil {

    private final String[] IP_HEADER_CANDIDATES = {
            "X-Forwarded-For",
            "X-FORWARDED-FOR",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "HTTP_VIA",
            "REMOTE_ADDR"
    };


    protected static String getClientIp(HttpServletRequest request) {

        log.info("TO GET CLIENT IP");
        for (String header : IP_HEADER_CANDIDATES) {
            String ip = request.getHeader(header);
            log.debug("HEADER:" + header);
            log.debug("HEADER VALUE:" + ip);
            if (ip != null && ip.length() != 0 && !"unknown".equalsIgnoreCase(ip)) {
                return ip;
            }
        }

        return request.getRemoteAddr();
    }
}
