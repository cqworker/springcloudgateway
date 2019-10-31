package com.example.demogateway;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Created by cheng on 2019/10/31.
 */
@Configuration
public class GateWayConfig {

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {

        return builder.routes()
                .route(r -> r.path("/miniprogram/account/testLogin;/miniprogram/account/wxGrantLogin")
                        .filters(f -> f.filter(new AddTokenFilter())
                                .stripPrefix(1))
                        .uri("lb://server-video")
                        .order(0)
                        .id("login-video")
                )
                .route(r -> r.path("/operation/user/login")
                        .filters(f -> f.filter(new AddTokenFilter())
                                .stripPrefix(1))
                        .uri("lb://server-doctor")
                        .order(0)
                        .id("login-doctor")
                )
                .build();
    }

}
