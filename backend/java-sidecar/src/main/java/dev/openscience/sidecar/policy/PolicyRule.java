package dev.openscience.sidecar.policy;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record PolicyRule(
    @NotNull @Size(max = 256) String permission,
    @NotNull @Size(max = 4096) String pattern,
    @NotNull Action action) {}
