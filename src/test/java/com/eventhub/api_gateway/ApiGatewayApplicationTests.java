package com.eventhub.api_gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
		"GATEWAY_INTERNAL_SECRET=test-gateway-secret",
		"JWT_SECRET=dGVzdC1zZWNyZXQtd2l0aC1hdC1sZWFzdC0zMi1ieXRlcw=="
})
class ApiGatewayApplicationTests {

	@Test
	void contextLoads() {
	}

}
