package dev.openscience.sidecar;

import dev.openscience.sidecar.policy.PolicyEvaluator;
import dev.openscience.sidecar.policy.PolicyRequest;
import dev.openscience.sidecar.policy.PolicyResponse;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1")
public final class SidecarController {
  private static final String PROTOCOL = "1";
  private final PolicyEvaluator evaluator;

  public SidecarController(PolicyEvaluator evaluator) {
    this.evaluator = evaluator;
  }

  @GetMapping("/health")
  Health health() {
    return new Health("ok", "openscience-java-sidecar", PROTOCOL);
  }

  @GetMapping("/capabilities")
  Capabilities capabilities() {
    return new Capabilities(PROTOCOL, List.of("permission.evaluate.shadow"));
  }

  @PostMapping("/policy/evaluate")
  PolicyResponse evaluate(@Valid @RequestBody PolicyRequest request) {
    var decision = evaluator.evaluate(request.permission(), request.pattern(), request.rules());
    return new PolicyResponse(PROTOCOL, decision);
  }

  record Health(String status, String service, String protocolVersion) {}

  record Capabilities(String protocolVersion, List<String> capabilities) {}
}
