package com.example.GateWayServer.validator;

import java.util.List;
import java.util.function.Predicate;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;



@Component
public class RouteValidatior {
	
	
	 public static final List<String> openApiEndpoints = List.of(
	            "/auth/user/register",
	            "/auth/user/token",
	            "/eureka"
	    );
	 
	 public Predicate<ServerHttpRequest> isSecured =
	            request -> openApiEndpoints
	                    .stream()
	                    .noneMatch(uri -> request.getURI().getPath().contains(uri));

}
