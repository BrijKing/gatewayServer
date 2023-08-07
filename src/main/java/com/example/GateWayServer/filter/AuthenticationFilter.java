package com.example.GateWayServer.filter;

import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

import com.example.GateWayServer.utils.JwtUtils;
import com.example.GateWayServer.validator.RouteValidatior;
import com.netflix.discovery.converters.Auto;

import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

	
	@Autowired
    private RouteValidatior validator;

    //    @Autowired
//    private RestTemplate template;
    @Autowired
    private JwtUtils jwtUtil;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (validator.isSecured.test(exchange.getRequest())) {
                //header contains token or not
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                	 ServerHttpResponse response = exchange.getResponse();
                     response.setStatusCode(HttpStatus.UNAUTHORIZED);
                     byte[] responseBytes = "JWT token not found".getBytes(StandardCharsets.UTF_8);
                     DataBuffer buffer = response.bufferFactory().wrap(responseBytes);
                     return response.writeWith(Mono.just(buffer));
                }

                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }
                try {
//                    //REST call to AUTH service
//                    template.getForObject("http://IDENTITY-SERVICE//validate?token" + authHeader, String.class);
                    jwtUtil.validateToken(authHeader);

                } catch (Exception e) {
//                    
                	System.out.println("invalid access...!");
                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    byte[] responseBytes = "Unauthorized access to the application".getBytes(StandardCharsets.UTF_8);
                    DataBuffer buffer = response.bufferFactory().wrap(responseBytes);
                    return response.writeWith(Mono.just(buffer));
                }
            }
            return chain.filter(exchange);
        });
    }

    public static class Config {

    }
}


	


