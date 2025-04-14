package auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.Map;

public class ConfirmForgotPasswordHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final CognitoIdentityProviderClient cognitoClient;
    private final String clientId;
    private final ObjectMapper objectMapper;

    public ConfirmForgotPasswordHandler() {
        this.cognitoClient = CognitoIdentityProviderClient.create();
        this.clientId = System.getenv("USER_POOL_CLIENT_ID");
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            // Parse request body
            Map<String, String> requestBody = objectMapper.readValue(input.getBody(), Map.class);
            String username = requestBody.get("username");
            String confirmationCode = requestBody.get("confirmationCode");
            String newPassword = requestBody.get("newPassword");

            if (username == null || confirmationCode == null || newPassword == null) {
                response.setStatusCode(400);
                response.setBody("{\"message\": \"Username, confirmation code, and new password are required\"}");
                return response;
            }

            // Confirm forgot password
            ConfirmForgotPasswordRequest confirmRequest = ConfirmForgotPasswordRequest.builder()
                    .clientId(clientId)
                    .username(username)
                    .confirmationCode(confirmationCode)
                    .password(newPassword)
                    .build();

            ConfirmForgotPasswordResponse confirmResponse = cognitoClient.confirmForgotPassword(confirmRequest);

            response.setStatusCode(200);
            response.setBody("{\"message\": \"Password has been reset successfully\"}");

        } catch (CodeMismatchException e) {
            response.setStatusCode(400);
            response.setBody("{\"message\": \"Invalid verification code\"}");
        } catch (ExpiredCodeException e) {
            response.setStatusCode(400);
            response.setBody("{\"message\": \"Verification code has expired\"}");
        } catch (InvalidPasswordException e) {
            response.setStatusCode(400);
            response.setBody("{\"message\": \"Password does not meet requirements: " + e.getMessage() + "\"}");
        } catch (Exception e) {
            context.getLogger().log("Error confirming password reset: " + e.getMessage());
            response.setStatusCode(500);
            response.setBody("{\"message\": \"Error confirming password reset: " + e.getMessage() + "\"}");
        }

        return response;
    }
}