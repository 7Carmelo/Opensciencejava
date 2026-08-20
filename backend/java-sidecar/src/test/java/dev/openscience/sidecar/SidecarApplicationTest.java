package dev.openscience.sidecar;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(
    classes = SidecarApplication.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class SidecarApplicationTest {
  @Autowired private WebTestClient client;

  @Test
  void healthDescribesTheRunningProtocol() {
    client
        .get()
        .uri("/v1/health")
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody()
        .jsonPath("$.status")
        .isEqualTo("ok")
        .jsonPath("$.service")
        .isEqualTo("openscience-java-sidecar")
        .jsonPath("$.protocolVersion")
        .isEqualTo("1");
  }

  @Test
  void capabilitiesAdvertiseShadowPolicyEvaluation() {
    client
        .get()
        .uri("/v1/capabilities")
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody()
        .jsonPath("$.protocolVersion")
        .isEqualTo("1")
        .jsonPath("$.capabilities[0]")
        .isEqualTo("permission.evaluate.shadow");
  }

  @Test
  void policyEndpointReturnsTheLastMatchingDecision() {
    var request =
        Map.of(
            "protocolVersion",
            "1",
            "permission",
            "bash",
            "pattern",
            "ls -la",
            "rules",
            List.of(
                Map.of("permission", "bash", "pattern", "ls *", "action", "allow"),
                Map.of("permission", "bash", "pattern", "ls -la", "action", "deny")));

    client
        .post()
        .uri("/v1/policy/evaluate")
        .bodyValue(request)
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody()
        .jsonPath("$.protocolVersion")
        .isEqualTo("1")
        .jsonPath("$.decision.permission")
        .isEqualTo("bash")
        .jsonPath("$.decision.pattern")
        .isEqualTo("ls -la")
        .jsonPath("$.decision.action")
        .isEqualTo("deny");
  }

  @Test
  void policyEndpointRejectsBlankPermission() {
    var request =
        Map.of(
            "protocolVersion",
            "1",
            "permission",
            "",
            "pattern",
            "ls",
            "rules",
            List.of());

    client
        .post()
        .uri("/v1/policy/evaluate")
        .bodyValue(request)
        .exchange()
        .expectStatus()
        .isBadRequest();
  }

  @Test
  void policyEndpointRejectsNullRules() {
    var request =
        Map.of(
            "protocolVersion",
            "1",
            "permission",
            "bash",
            "pattern",
            "ls",
            "rules",
            Collections.singletonList(null));

    client
        .post()
        .uri("/v1/policy/evaluate")
        .bodyValue(request)
        .exchange()
        .expectStatus()
        .isBadRequest();
  }

  @Test
  void policyEndpointRejectsActionsThatAreNotLowercase() {
    var request =
        Map.of(
            "protocolVersion",
            "1",
            "permission",
            "bash",
            "pattern",
            "ls",
            "rules",
            List.of(Map.of("permission", "bash", "pattern", "ls *", "action", "ALLOW")));

    client
        .post()
        .uri("/v1/policy/evaluate")
        .bodyValue(request)
        .exchange()
        .expectStatus()
        .isBadRequest();
  }

  @Test
  void policyEndpointRejectsOversizedPatterns() {
    var request =
        Map.of(
            "protocolVersion",
            "1",
            "permission",
            "bash",
            "pattern",
            "a".repeat(4_097),
            "rules",
            List.of());

    client
        .post()
        .uri("/v1/policy/evaluate")
        .bodyValue(request)
        .exchange()
        .expectStatus()
        .isBadRequest();
  }

  @Test
  void policyEndpointRejectsTooManyRules() {
    var rule = Map.of("permission", "bash", "pattern", "*", "action", "allow");
    var request =
        Map.of(
            "protocolVersion",
            "1",
            "permission",
            "bash",
            "pattern",
            "ls",
            "rules",
            Collections.nCopies(129, rule));

    client
        .post()
        .uri("/v1/policy/evaluate")
        .bodyValue(request)
        .exchange()
        .expectStatus()
        .isBadRequest();
  }
}
