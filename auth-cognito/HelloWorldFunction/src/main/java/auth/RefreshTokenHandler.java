package auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;

import java.util.HashMap;
import java.util.Map;

public class RefreshTokenHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final CognitoIdentityProviderClient cognitoClient;
    private final String clientId;
    private final ObjectMapper objectMapper;

    public RefreshTokenHandler() {
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
            String refreshToken = requestBody.get("refreshToken");

            if (refreshToken == null) {
                response.setStatusCode(400);
                response.setBody("{\"message\": \"Refresh token is required\"}");
                return response;
            }

            // Set up auth parameters
            Map<String, String> authParams = new HashMap<>();
            authParams.put("REFRESH_TOKEN", refreshToken);

            // Create Cognito auth request
            InitiateAuthRequest authRequest = InitiateAuthRequest.builder()
                    .clientId(clientId)
                    .authFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
                    .authParameters(authParams)
                    .build();

            // Initiate auth
            InitiateAuthResponse authResponse = cognitoClient.initiateAuth(authRequest);

            // Build response
            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", authResponse.authenticationResult().accessToken());
            tokens.put("idToken", authResponse.authenticationResult().idToken());

            // Cognito might not always return a new refresh token
            if (authResponse.authenticationResult().refreshToken() != null) {
                tokens.put("refreshToken", authResponse.authenticationResult().refreshToken());
            }

            response.setStatusCode(200);
            response.setBody(objectMapper.writeValueAsString(tokens));

        } catch (Exception e) {
            context.getLogger().log("Error refreshing token: " + e.getMessage());
            response.setStatusCode(401);
            response.setBody("{\"message\": \"Error refreshing token: " + e.getMessage() + "\"}");
        }

        return response;
    }
}