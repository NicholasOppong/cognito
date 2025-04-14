package auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GlobalSignOutRequest;

import java.util.Map;

public class SignOutHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final CognitoIdentityProviderClient cognitoClient;

    public SignOutHandler() {
        this.cognitoClient = CognitoIdentityProviderClient.create();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            // Extract access token from Authorization header
            String accessToken = input.getHeaders().get("Authorization").replace("Bearer ", "");

            // Sign out user
            GlobalSignOutRequest signOutRequest = GlobalSignOutRequest.builder()
                    .accessToken(accessToken)
                    .build();
            cognitoClient.globalSignOut(signOutRequest);

            response.setStatusCode(200);
            response.setBody("{\"message\": \"User signed out successfully\"}");

        } catch (Exception e) {
            response.setStatusCode(500);
            response.setBody("{\"message\": \"Error signing out: " + e.getMessage() + "\"}");
        }

        return response;
    }
}
