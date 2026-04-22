package main

import rego.v1

deny contains msg if {
  some result in input.Results
  some vuln in result.Vulnerabilities
  upper(object.get(vuln, "Severity", "UNKNOWN")) == "CRITICAL"
  object.get(vuln, "FixedVersion", "") != ""
  msg := sprintf("Fixable CRITICAL vulnerability found: %s in %s (fixed version: %s)", [
    vuln.VulnerabilityID,
    result.Target,
    object.get(vuln, "FixedVersion", "")
  ])
}

deny contains msg if {
  some result in input.Results
  some vuln in result.Vulnerabilities
  upper(object.get(vuln, "Severity", "UNKNOWN")) == "HIGH"
  object.get(vuln, "FixedVersion", "") != ""
  msg := sprintf("Fixable HIGH vulnerability found: %s in %s (fixed version: %s)", [
    vuln.VulnerabilityID,
    result.Target,
    object.get(vuln, "FixedVersion", "")
  ])
}