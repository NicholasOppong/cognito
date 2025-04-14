package auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.Test;
import static org.junit.Assert.*;

public class SignInHandlerTest {
    @Test
    public void testHandleRequest() {
        SignInHandler handler = new SignInHandler();
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        request.setBody("{\"username\":\"testuser\",\"password\":\"testpass\"}");
        
        APIGatewayProxyResponseEvent response = handler.handleRequest(request, null);
        
        assertNotNull(response);
        assertNotNull(response.getStatusCode());
        assertNotNull(response.getBody());
    }
}