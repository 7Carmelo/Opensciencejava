package dev.openscience.sidecar.policy;

import java.util.List;

public final class PolicyEvaluator {
  private static final int MAX_WORK = 100_000;

  public PolicyRule evaluate(String permission, String pattern, List<PolicyRule> rules) {
    var budget = new WildcardMatcher.Budget(MAX_WORK);
    for (var index = rules.size() - 1; index >= 0; index--) {
      var rule = rules.get(index);
      if (!WildcardMatcher.matches(permission, rule.permission(), budget)) continue;
      if (!WildcardMatcher.matches(pattern, rule.pattern(), budget)) continue;
      return rule;
    }
    return new PolicyRule(permission, "*", Action.ASK);
  }
}
