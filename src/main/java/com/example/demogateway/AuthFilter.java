package com.example.demogateway;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.example.demogateway.util.JwtTokenUtil;
import io.netty.buffer.ByteBufAllocator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.NettyDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Created by cheng on 2019/10/31.
 * 全局过滤器 不需要在配置文件中配置 作用在所有的路由上
 */
@Component
public class AuthFilter implements GlobalFilter, Ordered {
    public final Logger log = LogManager.getLogger(getClass());

    //   不需要验证token的白名单，使用分号;隔开
    @Value("${interceptor.auth-exclude-uris}")
    private String tokenFreeUris;
    @Value("${JWT.token-prefix}")
    private String tokenPrefix;
    @Value("${JWT.request-user-key}")
    private String userKey;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    private List<Pattern> tokenFreeUriPatternList = new LinkedList<Pattern>();

    /**
     * 初始化白名单
     */
    @PostConstruct
    public void init() {
        String[] tokenFreeUriList = tokenFreeUris.split(";");
        for (String uriRegex : tokenFreeUriList) {
            if (uriRegex != null && false == uriRegex.isEmpty()) {
                tokenFreeUriPatternList.add(Pattern.compile(uriRegex));
            }
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        HttpHeaders header = request.getHeaders();
        HttpMethod method = request.getMethod();

        if (method.equals("OPTIONS")) {
            //预检请求，不需要验证,放行
            return chain.filter(exchange);
        }

        String requestUri = request.getURI().getPath();
        for (Pattern p : tokenFreeUriPatternList) {
            if (p.matcher(requestUri).find() == true) {
                //白名单不用验证token
                return chain.filter(exchange);
            }
        }
        //从header中获取token信息
        String token = header.getFirst("Authorization");
        if (token != null) {
//           1. 验证token是否有效
            if (token.startsWith(tokenPrefix)) {
                token = token.replaceFirst(tokenPrefix, "");
                Map<String, String> infoMap = null;
                try {
                    infoMap = jwtTokenUtil.parseJWT(token);
                } catch (Exception e) {
                    log.info("jwt解析token出错");
                    ServerHttpResponse serverHttpResponse = exchange.getResponse();
                    serverHttpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
                    //todo  如何重写response
                    byte[] bytes = "{\"result\": false,\"code\": \"000004\",\"msg\": \"token校验失败\",\"data\": \"\"}".getBytes(StandardCharsets.UTF_8);
                    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
                    return exchange.getResponse().writeWith(Flux.just(buffer));
                }
                log.info("解析token获取信息为:{}", infoMap);
// 令牌验证通过，抽取令牌所带信息，放入请求头
                if (infoMap != null && infoMap.size() > 0) {
//                    重塑request
                    ServerHttpRequest.Builder mutate = request.mutate();
                    for (Map.Entry<String, String> entry : infoMap.entrySet()) {
                        mutate.header(entry.getKey(), entry.getValue());
                    }
                    ServerHttpRequest buildReuqest = mutate.build();
                    //todo 利用ServerHttpRequestDecorator来解析request，并修改内容
                    ServerHttpRequestDecorator serverHttpRequestDecorator = new ServerHttpRequestDecorator(request){
                        @Override
                        public Flux<DataBuffer> getBody() {
                            Flux<DataBuffer> body = super.getBody();
                            return body.map(dataBuffer -> {
                                byte[] content = new byte[dataBuffer.readableByteCount()];
                                dataBuffer.read(content);
                                //释放掉内存
                                DataBufferUtils.release(dataBuffer);
                                //这个就是request body的json格式数据
                                String bodyJson = new String(content, Charset.forName("UTF-8"));
                                //转化成json对象
                                JSONObject jsonObject = JSON.parseObject(bodyJson);
                                //把用户id和客户端id添加到json对象中
                                jsonObject.put("userId", "123");
                                String result = jsonObject.toJSONString();
                                //转成字节
                                byte[] bytes = result.getBytes();

                                NettyDataBufferFactory nettyDataBufferFactory = new NettyDataBufferFactory(ByteBufAllocator.DEFAULT);
                                DataBuffer buffer = nettyDataBufferFactory.allocateBuffer(bytes.length);
                                buffer.write(bytes);
                                return buffer;
                            });
                        }
                        //复写getHeaders方法，删除content-length
                        @Override
                        public HttpHeaders getHeaders() {
                            HttpHeaders httpHeaders = new HttpHeaders();
                            httpHeaders.putAll(super.getHeaders());
                            //由于修改了请求体的body，导致content-length长度不确定，因此使用分块编码
                            httpHeaders.remove(HttpHeaders.CONTENT_LENGTH);
                            httpHeaders.set(HttpHeaders.TRANSFER_ENCODING, "chunked");
                            return httpHeaders;
                        }


                    };
                    return chain.filter(exchange.mutate().request(buildReuqest).build());
                }else {
                    ServerHttpResponse serverHttpResponse = exchange.getResponse();
                    serverHttpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
                    //todo
                    byte[] bytes = "{\"result\": false,\"code\": \"000005\",\"msg\": \"token校验失败\",\"data\": \"\"}".getBytes(StandardCharsets.UTF_8);
                    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
                    return exchange.getResponse().writeWith(Flux.just(buffer));
                }

            }
        }else{
            //未携带token
            ServerHttpResponse serverHttpResponse = exchange.getResponse();
            serverHttpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
            byte[] bytes = "{\"result\": false,\"code\": \"000004\",\"msg\": \"未登录\",\"data\": \"\"}".getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Flux.just(buffer));
        }
        return chain.filter(exchange);
    }


    @Override
    public int getOrder() {
        return 0;
    }
}
