package auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChangePasswordRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChangePasswordResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.NotAuthorizedException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InvalidPasswordException;

import java.util.Map;

public class ChangePasswordHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final CognitoIdentityProviderClient cognitoClient;
    private final ObjectMapper objectMapper;

    public ChangePasswordHandler() {
        this.cognitoClient = CognitoIdentityProviderClient.create();
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            // Get the access token
            String authHeader = input.getHeaders().get("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                response.setStatusCode(401);
                response.setBody("{\"message\": \"Unauthorized - Invalid token\"}");
                return response;
            }

            String accessToken = authHeader.substring(7); // Remove "Bearer " prefix

            // Parse request body
            Map<String, String> requestBody = objectMapper.readValue(input.getBody(), Map.class);
            String previousPassword = requestBody.get("previousPassword");
            String newPassword = requestBody.get("newPassword");

            if (previousPassword == null || newPassword == null) {
                response.setStatusCode(400);
                response.setBody("{\"message\": \"Previous password and new password are required\"}");
                return response;
            }

            // Change password
            ChangePasswordRequest changePasswordRequest = ChangePasswordRequest.builder()
                    .accessToken(accessToken)
                    .previousPassword(previousPassword)
                    .proposedPassword(newPassword)
                    .build();

            ChangePasswordResponse changePasswordResponse = cognitoClient.changePassword(changePasswordRequest);

            response.setStatusCode(200);
            response.setBody("{\"message\": \"Password changed successfully\"}");

        } catch (NotAuthorizedException e) {
            response.setStatusCode(401);
            response.setBody("{\"message\": \"Incorrect previous password\"}");
        } catch (InvalidPasswordException e) {
            response.setStatusCode(400);
            response.setBody("{\"message\": \"Password does not meet requirements: " + e.getMessage() + "\"}");
        } catch (Exception e) {
            context.getLogger().log("Error changing password: " + e.getMessage());
            response.setStatusCode(500);
            response.setBody("{\"message\": \"Error changing password: " + e.getMessage() + "\"}");
        }

        return response;
    }
}