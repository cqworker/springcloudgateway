package com.example.demogateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @Desc jwt令牌工具类
 * @Date 2019/3/11
 */
@Component("jwtTokenUtil")
public class JwtTokenUtil {

    @Value("${JWT.jwt-key}")
    private String jwtKey;
    @Value("${JWT.token-expiration-time}")
    private long tokenExpirationtime;
    @Value("${JWT.token-prefix}")
    private String tokenPrefix;
    @Value("${JWT.request-user-key}")
    private String userKey;

    /**
     * 加密userSysid 获取tokenStr
     * @param userSysid 用户id
     * @return tokenStr
     */
    public String getTokenStr(String userSysid) {
        Date exp = new Date(System.currentTimeMillis() + tokenExpirationtime * 1000);
        Map<String, String> infoMap = new HashMap<>(5);
        infoMap.put(userKey, userSysid);
        String tokenStr = createJwT(infoMap, exp);
        return tokenPrefix + tokenStr;
    }

    /**
     * 创建jwt令牌
     * @param infoMap 信息map
     * @param tokenExpiration token过期时间
     * @return 令牌str
     */
    private String createJwT(Map<String, String> infoMap, Date tokenExpiration) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(jwtKey);
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
        Map<String, Object> claims = new HashMap<>(infoMap);
        claims.put(Claims.ID, UUID.randomUUID());
        JwtBuilder builder = Jwts.builder()
                .setClaims(claims)
                .signWith(signatureAlgorithm, signingKey);
        if(null != tokenExpiration) {
            builder.setExpiration(tokenExpiration);
        }
        return builder.compact();
    }

    /**
     * 解密jwt令牌
     * @param jwt jwt令牌
     * @return 信息map
     */
    public Map<String, String> parseJWT(String jwt) {
        Claims claims = Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(jwtKey))
                .parseClaimsJws(jwt).getBody();
        Map<String,String> result = new HashMap<>(5);
        //去除系统信息
        claims.remove(Claims.ISSUER);
        claims.remove(Claims.SUBJECT);
        claims.remove(Claims.AUDIENCE);
        claims.remove(Claims.EXPIRATION);
        claims.remove(Claims.NOT_BEFORE);
        claims.remove(Claims.ISSUED_AT);
        claims.remove(Claims.ID);
        for(Map.Entry<String, Object> en : claims.entrySet()) {
            result.put(en.getKey(), (String)en.getValue());
        }
        return result;
    }
}
