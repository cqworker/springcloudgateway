package com.example.demogateway;

import com.alibaba.fastjson.JSONObject;
import com.example.demogateway.util.JwtTokenUtil;
import com.example.demogateway.util.SpringUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.Charset;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 只拦截登录响应
 */
public class AddTokenFilter implements GatewayFilter, Ordered {

    public final Logger log = LogManager.getLogger(getClass());


    @Value("${interceptor.give-token-uris}")
    private String giveTokenUris;
    private JwtTokenUtil jwtTokenUtil;

    private List<Pattern> giveTokenUriPatternList = new LinkedList<Pattern>();

    @PostConstruct
    public void init() {
        String[] giveTokenUriList = giveTokenUris.split(";");
        for (String uriRegex : giveTokenUriList) {
            if (uriRegex != null && false == uriRegex.isEmpty()) {
                giveTokenUriPatternList.add(Pattern.compile(uriRegex));
            }
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        jwtTokenUtil = (JwtTokenUtil) SpringUtil.getBean("jwtTokenUtil");
        ServerHttpResponse originalResponse = exchange.getResponse();
        DataBufferFactory bufferFactory = originalResponse.bufferFactory();

        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                if (body instanceof Flux) {
                    Flux<? extends DataBuffer> fluxBody = (Flux<? extends DataBuffer>) body;
                    return super.writeWith(fluxBody.map(dataBuffer -> {
                        // probably should reuse buffers
                        byte[] content = new byte[dataBuffer.readableByteCount()];
                        dataBuffer.read(content);
                        //释放掉内存
                        DataBufferUtils.release(dataBuffer);
                        String s = new String(content, Charset.forName("UTF-8"));
                        //重写response start
                        JSONObject jsonObject = JSONObject.parseObject(s);
                        String code = jsonObject.getString("code");
                        boolean result = jsonObject.getBoolean("result");
                        HttpStatus statusCode = originalResponse.getStatusCode();
                        if (200 == statusCode.value() && result && "000000".equals(code)) {
                            JSONObject data = jsonObject.getJSONObject("data");
                            String userId = data.getString("userId");
                            String roleList = data.getJSONArray("roleList").toJSONString();
                            String token = jwtTokenUtil.getTokenStr(userId);
                            s = "{\n" +
                                    "    \"result\": true,\n" +
                                    "    \"code\": \"000000\",\n" +
                                    "    \"msg\": \"\",\n" +
                                    "    \"data\": {\n" +
                                    "        \"token\":\" " + token + "\",\n" +
                                    "        \"roleList\": " + roleList + "\n" +
                                    "    }\n" +
                                    "}";
                        } else {
                            //认证失败
                            s = "{\n" +
                                    "    \"result\": true,\n" +
                                    "    \"code\": \"000001\",\n" +
                                    "    \"msg\": \"用户名或密码错误\",\n" +
                                    "    \"data\":{}\n" +
                                    "}";
                        }

                        byte[] uppedContent = new String(s.getBytes(), Charset.forName("UTF-8")).getBytes();
                        return bufferFactory.wrap(uppedContent);
                    }));
                }
                // if body is not a flux. never got there.
                return super.writeWith(body);
            }
        };
        // replace response with decorator
        return chain.filter(exchange.mutate().response(decoratedResponse).build());


    }

    @Override
    public int getOrder() {
        //https://github.com/spring-cloud/spring-cloud-gateway/issues/47
        //在filter回调中debug查看s的值,order要设置的足够小
        return -5;
    }
}
