package auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.Map;

public class ForgotPasswordHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final CognitoIdentityProviderClient cognitoClient;
    private final String clientId;
    private final ObjectMapper objectMapper;

    public ForgotPasswordHandler() {
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

            if (username == null || username.isEmpty()) {
                response.setStatusCode(400);
                response.setBody("{\"message\": \"Username is required\"}");
                return response;
            }

            // Initiate forgot password flow
            ForgotPasswordRequest forgotPasswordRequest = ForgotPasswordRequest.builder()
                    .clientId(clientId)
                    .username(username)
                    .build();

            ForgotPasswordResponse forgotPasswordResponse = cognitoClient.forgotPassword(forgotPasswordRequest);

            response.setStatusCode(200);
            response.setBody("{\"message\": \"Password reset code sent to associated delivery destination\", " +
                    "\"deliveryMedium\": \"" + forgotPasswordResponse.codeDeliveryDetails().deliveryMedium() + "\", " +
                    "\"destination\": \"" + forgotPasswordResponse.codeDeliveryDetails().destination() + "\"}");

        } catch (UserNotFoundException e) {
            // For security reasons, don't reveal whether the user exists or not
            response.setStatusCode(200);
            response.setBody("{\"message\": \"If the username exists, a password reset code will be sent\"}");
        } catch (Exception e) {
            context.getLogger().log("Error in forgot password flow: " + e.getMessage());
            response.setStatusCode(500);
            response.setBody("{\"message\": \"Error in forgot password flow: " + e.getMessage() + "\"}");
        }

        return response;
    }
}