package main

import rego.v1

# Helper to fetch a string field and fall back to empty
get_field = val if {
  v := object.get(vuln, "FixedVersion", "")
  val := trim(v, "")  # properly call trim with two arguments
}

deny contains msg if {
  some result in input.Results
  some vuln in result.Vulnerabilities
  sev := upper(object.get(vuln, "Severity", "UNKNOWN"))
  sev == "CRITICAL"
  # Get FixedVersion; if it's non-empty, a fix is available
  fv := object.get(vuln, "FixedVersion", "")
  fv != ""
  msg := sprintf("Fixable CRITICAL vulnerability found: %s in %s (fixed version: %s)", [vuln.VulnerabilityID, result.Target, fv])
}

deny contains msg if {
  some result in input.Results
  some vuln in result.Vulnerabilities
  sev := upper(object.get(vuln, "Severity", "UNKNOWN"))
  sev == "HIGH"
  fv := object.get(vuln, "FixedVersion", "")
  fv != ""
  msg := sprintf("Fixable HIGH vulnerability found: %s in %s (fixed version: %s)", [vuln.VulnerabilityID, result.Target, fv])
}