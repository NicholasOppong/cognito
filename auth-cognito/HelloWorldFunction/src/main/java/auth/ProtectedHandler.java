package auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.Map;

public class ProtectedHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final ObjectMapper objectMapper;

    public ProtectedHandler() {
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            // Get Cognito claims from request context
            Map<String, Object> authorizer = input.getRequestContext().getAuthorizer();
            Map<String, String> claims = (Map<String, String>) authorizer.get("claims");

            // Extract user details
            String email = claims.get("email");
            String sub = claims.get("sub"); // Cognito user ID

            // Build response
            Map<String, String> userInfo = new HashMap<>();
            userInfo.put("message", "Access granted to protected resource");
            userInfo.put("email", email);
            userInfo.put("userId", sub);

            response.setStatusCode(200);
            response.setBody(objectMapper.writeValueAsString(userInfo));

        } catch (Exception e) {
            response.setStatusCode(500);
            response.setBody("{\"message\": \"Error accessing protected resource: " + e.getMessage() + "\"}");
        }

        return response;
    }
}
