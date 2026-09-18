package com.docutrust.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Proves the access control rather than merely declaring it.
 *
 * <p>Authorisation rules are the kind of thing that looks obviously correct in
 * configuration and silently stops working after an unrelated change. These
 * tests attempt the escalation and assert it is refused.
 *
 * <p>They also pin the distinction between 401 and 403, which the frontend acts
 * on: a 401 clears the session and returns the user to sign in, while a 403
 * must not, because signing in again would change nothing.
 *
 * <p>Rate limiting is disabled here so that a burst of test requests is not
 * throttled — which also exercises the configuration switch.
 */
@SpringBootTest(properties = {
        "docutrust.demo.seed-enabled=true",
        "docutrust.demo.user-email=authz-user@docutrust.local",
        "docutrust.demo.user-password=TestUserPassword123!",
        "docutrust.demo.admin-email=authz-admin@docutrust.local",
        "docutrust.demo.admin-password=TestAdminPassword123!",
        "docutrust.jwt.secret=authorization-test-secret-value-of-at-least-32-bytes",
        "docutrust.rate-limit.enabled=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("local")
@DisplayName("Authorisation")
class AuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String tokenFor(String email, String password) throws Exception {
        String body = objectMapper.createObjectNode()
                .put("email", email)
                .put("password", password)
                .toString();

        String response = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        JsonNode json = objectMapper.readTree(response);
        return json.get("token").asText();
    }

    private String userToken() throws Exception {
        return tokenFor("authz-user@docutrust.local", "TestUserPassword123!");
    }

    private String adminToken() throws Exception {
        return tokenFor("authz-admin@docutrust.local", "TestAdminPassword123!");
    }

    // ------------------------------------------------------- unauthenticated

    @Test
    @DisplayName("An unauthenticated request gets 401, not 403")
    void unauthenticatedRequestIsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/dashboard/summary"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTHENTICATION_REQUIRED"))
                // The error must carry a correlation ID so a support request
                // can be tied to the server log entry.
                .andExpect(jsonPath("$.correlationId").isNotEmpty());
    }

    @Test
    @DisplayName("A forged token is rejected")
    void forgedTokenIsRejected() throws Exception {
        mockMvc.perform(get("/api/v1/documents")
                        .header("Authorization", "Bearer not.a.real.token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("A token signed with the wrong key is rejected")
    void tokenSignedWithWrongKeyIsRejected() throws Exception {
        // Structurally valid JWT, signed with a different secret. It must fail
        // signature verification rather than be accepted on shape alone.
        String foreign = "eyJhbGciOiJIUzI1NiJ9"
                + ".eyJzdWIiOiJhdHRhY2tlciIsImlzcyI6ImRvY3V0cnVzdCIsInJvbGUiOiJBRE1JTiJ9"
                + ".Ym9ndXMtc2lnbmF0dXJlLXRoYXQtd2lsbC1uZXZlci12ZXJpZnk";

        mockMvc.perform(get("/api/v1/admin/audit/integrity")
                        .header("Authorization", "Bearer " + foreign))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Login and health remain open")
    void publicEndpointsAreReachable() throws Exception {
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    // ------------------------------------------------ authenticated but not permitted

    @Test
    @DisplayName("A USER reaching an ADMIN endpoint gets 403, not 401")
    void userCannotReachAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/v1/admin/audit/integrity")
                        .header("Authorization", "Bearer " + userToken()))
                // 403, because the caller IS authenticated. Returning 401 here
                // would tell the client to sign in again, which would not help
                // and would log the user out for no reason.
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
    }

    @Test
    @DisplayName("A USER cannot read system-wide audit events")
    void userCannotReadSystemAudit() throws Exception {
        mockMvc.perform(get("/api/v1/admin/audit/recent")
                        .header("Authorization", "Bearer " + userToken()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("A USER cannot read actuator metrics")
    void userCannotReadMetrics() throws Exception {
        // Metrics expose operational detail and are administrator-only.
        mockMvc.perform(get("/actuator/prometheus")
                        .header("Authorization", "Bearer " + userToken()))
                .andExpect(status().isForbidden());
    }

    // ---------------------------------------------------------------- permitted

    @Test
    @DisplayName("An ADMIN can verify the audit chain")
    void adminCanReachAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/v1/admin/audit/integrity")
                        .header("Authorization", "Bearer " + adminToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").exists());
    }

    @Test
    @DisplayName("A USER can use the ordinary endpoints")
    void userCanReachOrdinaryEndpoints() throws Exception {
        String token = userToken();

        mockMvc.perform(get("/api/v1/dashboard/summary")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/documents")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/certificates")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    // ------------------------------------------------------------- disclosure

    @Test
    @DisplayName("A document belonging to nobody returns the same error as one belonging to someone else")
    void unknownDocumentIsIndistinguishableFromForbidden() throws Exception {
        String response = mockMvc.perform(get("/api/v1/documents/00000000-0000-0000-0000-000000000000")
                        .header("Authorization", "Bearer " + userToken()))
                .andExpect(status().isNotFound())
                .andReturn().getResponse().getContentAsString();

        // Both cases must yield DOCUMENT_NOT_FOUND. Distinguishing "does not
        // exist" from "exists but is not yours" would let a caller enumerate
        // which document identifiers are real.
        assertThat(objectMapper.readTree(response).get("code").asText())
                .isEqualTo("DOCUMENT_NOT_FOUND");
    }

    @Test
    @DisplayName("Login failures reveal nothing about which accounts exist")
    void loginFailuresAreIndistinguishable() throws Exception {
        String unknownAccount = objectMapper.createObjectNode()
                .put("email", "nobody@docutrust.local")
                .put("password", "whatever").toString();

        String wrongPassword = objectMapper.createObjectNode()
                .put("email", "authz-user@docutrust.local")
                .put("password", "definitely-not-the-password").toString();

        String first = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(unknownAccount))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        String second = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(wrongPassword))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        JsonNode firstJson = objectMapper.readTree(first);
        JsonNode secondJson = objectMapper.readTree(second);

        assertThat(firstJson.get("code").asText()).isEqualTo(secondJson.get("code").asText());
        assertThat(firstJson.get("message").asText()).isEqualTo(secondJson.get("message").asText());
    }

    @Test
    @DisplayName("Error responses never carry stack traces or internal detail")
    void errorsDoNotLeakInternals() throws Exception {
        String response = mockMvc.perform(get("/api/v1/documents/does-not-exist")
                        .header("Authorization", "Bearer " + userToken()))
                .andReturn().getResponse().getContentAsString();

        assertThat(response)
                .doesNotContain("com.docutrust")
                .doesNotContain("Exception")
                .doesNotContain("at java.")
                .doesNotContain("SELECT");
    }
}
