package auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;

public class AdminCreateUserHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final CognitoIdentityProviderClient cognitoClient;
    private final String userPoolId;
    private final ObjectMapper objectMapper;

    public AdminCreateUserHandler() {
        this.cognitoClient = CognitoIdentityProviderClient.create();
        this.userPoolId = System.getenv("USER_POOL_ID");
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            // Get the caller's identity from the JWT token
            String authHeader = input.getHeaders().get("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                response.setStatusCode(401);
                response.setBody("{\"message\": \"Unauthorized - Invalid token\"}");
                return response;
            }

            String accessToken = authHeader.substring(7); // Remove "Bearer " prefix

            // Check if the user is an admin
            AdminGetUserRequest adminGetUserRequest = AdminGetUserRequest.builder()
                    .accessToken(accessToken)
                    .build();

            // Verify admin group membership
            try {
                // Use ListGroupsForUser to check if user is in Admins group
                ListGroupsForUserRequest listGroupsRequest = ListGroupsForUserRequest.builder()
                        .username(getCognitoUsername(accessToken))
                        .userPoolId(userPoolId)
                        .build();

                ListGroupsForUserResponse listGroupsResponse = cognitoClient.listGroupsForUser(listGroupsRequest);

                boolean isAdmin = listGroupsResponse.groups().stream()
                        .anyMatch(group -> "Admins".equals(group.groupName()));

                if (!isAdmin) {
                    response.setStatusCode(403);
                    response.setBody("{\"message\": \"Forbidden - Admin access required\"}");
                    return response;
                }
            } catch (Exception e) {
                response.setStatusCode(403);
                response.setBody("{\"message\": \"Forbidden - Admin access required\"}");
                return response;
            }

            // Parse request body
            Map<String, String> requestBody = objectMapper.readValue(input.getBody(), Map.class);
            String email = requestBody.get("email");
            String name = requestBody.get("name");

            if (email == null || email.isEmpty()) {
                response.setStatusCode(400);
                response.setBody("{\"message\": \"Email is required\"}");
                return response;
            }

            // Prepare user attributes
            List<AttributeType> userAttributes = new ArrayList<>();
            userAttributes.add(AttributeType.builder().name("email").value(email).build());
            userAttributes.add(AttributeType.builder().name("email_verified").value("true").build());

            if (name != null && !name.isEmpty()) {
                userAttributes.add(AttributeType.builder().name("name").value(name).build());
            }

            // Create user with temporary password
            AdminCreateUserRequest createUserRequest = AdminCreateUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(email)
                    .temporaryPassword(generateTemporaryPassword())
                    .userAttributes(userAttributes)
                    .messageAction(MessageActionType.SUPPRESS) // We'll handle email notification separately
                    .build();

            AdminCreateUserResponse createUserResult = cognitoClient.adminCreateUser(createUserRequest);

            // Send welcome email with temporary password (implement this part separately)
            // sendWelcomeEmail(email, temporaryPassword);

            response.setStatusCode(201);
            response.setBody("{\"message\": \"User created successfully\", \"user\": \"" +
                    createUserResult.user().username() + "\", " +
                    "\"password\": \"" + createUserRequest.temporaryPassword() + "\"}");

        } catch (UserNotFoundException e) {
            response.setStatusCode(404);
            response.setBody("{\"message\": \"User not found\"}");
        } catch (UsernameExistsException e) {
            response.setStatusCode(400);
            response.setBody("{\"message\": \"Username already exists\"}");
        } catch (Exception e) {
            context.getLogger().log("Error creating user: " + e.getMessage());
            response.setStatusCode(500);
            response.setBody("{\"message\": \"Error creating user: " + e.getMessage() + "\"}");
        }

        return response;
    }

    private String getCognitoUsername(String accessToken) {
        GetUserRequest getUserRequest = GetUserRequest.builder()
                .accessToken(accessToken)
                .build();
        GetUserResponse getUserResponse = cognitoClient.getUser(getUserRequest);
        return getUserResponse.username();
    }

    private String generateTemporaryPassword() {
        // Generate a secure random password
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        StringBuilder password = new StringBuilder();
        java.util.Random random = new java.util.Random();

        // Generate 12-character password
        for (int i = 0; i < 12; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }

        return password.toString();
    }
}