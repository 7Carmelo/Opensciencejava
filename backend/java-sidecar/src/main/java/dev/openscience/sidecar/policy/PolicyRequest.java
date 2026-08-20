package dev.openscience.sidecar.policy;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;

public record PolicyRequest(
    @NotBlank @Pattern(regexp = "1") String protocolVersion,
    @NotBlank @Size(max = 256) String permission,
    @NotNull @Size(max = 4096) String pattern,
    @NotNull @Size(max = 128) List<@NotNull @Valid PolicyRule> rules) {}
