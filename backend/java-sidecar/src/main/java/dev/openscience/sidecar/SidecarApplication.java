package dev.openscience.sidecar;

import dev.openscience.sidecar.policy.PolicyEvaluator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SidecarApplication {
  public static void main(String[] args) {
    SpringApplication.run(SidecarApplication.class, args);
  }

  @Bean
  PolicyEvaluator policyEvaluator() {
    return new PolicyEvaluator();
  }
}
