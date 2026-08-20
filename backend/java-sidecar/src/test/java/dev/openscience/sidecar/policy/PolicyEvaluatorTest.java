package dev.openscience.sidecar.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class PolicyEvaluatorTest {
  private final PolicyEvaluator evaluator = new PolicyEvaluator();

  @Test
  void lastMatchingRuleWins() {
    var rules =
        List.of(
            new PolicyRule("*", "*", Action.ASK),
            new PolicyRule("bash", "ls *", Action.ALLOW),
            new PolicyRule("bash", "ls -la", Action.DENY));

    assertThat(evaluator.evaluate("bash", "ls -la", rules))
        .isEqualTo(new PolicyRule("bash", "ls -la", Action.DENY));
  }

  @Test
  void wildcardPermissionAndQuestionMarkMatch() {
    var rules = List.of(new PolicyRule("web*", "exa?ple.com/*", Action.ALLOW));

    assertThat(evaluator.evaluate("webfetch", "example.com/paper", rules))
        .isEqualTo(new PolicyRule("web*", "exa?ple.com/*", Action.ALLOW));
  }

  @Test
  void trailingSpaceWildcardAlsoMatchesTheBareCommand() {
    var rules = List.of(new PolicyRule("bash", "ls *", Action.ALLOW));

    assertThat(evaluator.evaluate("bash", "ls", rules))
        .isEqualTo(new PolicyRule("bash", "ls *", Action.ALLOW));
  }

  @Test
  void questionMarkCountsUtf16CodeUnitsLikeTypeScript() {
    var one = List.of(new PolicyRule("bash", "?", Action.ALLOW));
    var two = List.of(new PolicyRule("bash", "??", Action.ALLOW));

    assertThat(evaluator.evaluate("bash", "😀", one))
        .isEqualTo(new PolicyRule("bash", "*", Action.ASK));
    assertThat(evaluator.evaluate("bash", "😀", two))
        .isEqualTo(new PolicyRule("bash", "??", Action.ALLOW));
  }

  @Test
  void regularExpressionCharactersRemainLiteral() {
    var rules = List.of(new PolicyRule("read", "file[1].txt", Action.ALLOW));

    assertThat(evaluator.evaluate("read", "file[1].txt", rules))
        .isEqualTo(new PolicyRule("read", "file[1].txt", Action.ALLOW));
    assertThat(evaluator.evaluate("read", "file1.txt", rules).action()).isEqualTo(Action.ASK);
  }

  @Test
  void unmatchedInputDefaultsToAsk() {
    assertThat(evaluator.evaluate("read", "/tmp/paper.md", List.of()))
        .isEqualTo(new PolicyRule("read", "*", Action.ASK));
  }

  @Test
  void largeLiteralPatternsStillMatch() {
    var value = "a".repeat(10_000);
    var pattern = "a".repeat(10_000);
    var rules = List.of(new PolicyRule("bash", pattern, Action.ALLOW));

    assertThat(evaluator.evaluate("bash", value, rules))
        .isEqualTo(new PolicyRule("bash", pattern, Action.ALLOW));
  }

  @Test
  void adversarialBacktrackingStopsAtTheSharedWorkBudget() {
    var value = "a".repeat(4_000);
    var attack = "*" + "a".repeat(2_000) + "b";
    var rules =
        List.of(
            new PolicyRule("bash", "*", Action.ALLOW),
            new PolicyRule("bash", attack, Action.DENY));

    assertThat(evaluator.evaluate("bash", value, rules))
        .isEqualTo(new PolicyRule("bash", "*", Action.ASK));
  }
}
