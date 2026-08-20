package dev.openscience.sidecar.policy;

public record PolicyResponse(String protocolVersion, PolicyRule decision) {}
