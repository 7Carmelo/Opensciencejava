package dev.openscience.sidecar.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Locale;

public enum Action {
  ALLOW,
  DENY,
  ASK;

  @JsonCreator
  public static Action fromJson(String value) {
    return switch (value) {
      case "allow" -> ALLOW;
      case "deny" -> DENY;
      case "ask" -> ASK;
      default -> throw new IllegalArgumentException("unknown policy action");
    };
  }

  @JsonValue
  public String toJson() {
    return name().toLowerCase(Locale.ROOT);
  }
}
