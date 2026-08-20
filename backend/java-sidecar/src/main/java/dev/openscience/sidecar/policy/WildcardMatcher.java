package dev.openscience.sidecar.policy;

final class WildcardMatcher {
  private WildcardMatcher() {}

  static boolean matches(String value, String wildcard, Budget budget) {
    if (wildcard.endsWith(" *")
        && glob(value, wildcard.substring(0, wildcard.length() - 2), budget)) {
      return true;
    }
    return glob(value, wildcard, budget);
  }

  private static boolean glob(String value, String wildcard, Budget budget) {
    var input = 0;
    var pattern = 0;
    var star = -1;
    var retry = -1;

    while (input < value.length()) {
      if (!budget.take()) return false;
      if (pattern < wildcard.length()) {
        var token = wildcard.charAt(pattern);
        if (token == '?' || token == value.charAt(input)) {
          input++;
          pattern++;
          continue;
        }
        if (token == '*') {
          star = pattern;
          retry = input;
          pattern++;
          continue;
        }
      }

      if (star == -1) return false;
      pattern = star + 1;
      retry++;
      input = retry;
    }

    while (pattern < wildcard.length()) {
      if (!budget.take()) return false;
      if (wildcard.charAt(pattern) != '*') return false;
      pattern++;
    }
    return true;
  }

  static final class Budget {
    private int remaining;

    Budget(int remaining) {
      this.remaining = remaining;
    }

    boolean take() {
      if (remaining == 0) return false;
      remaining--;
      return true;
    }
  }
}
