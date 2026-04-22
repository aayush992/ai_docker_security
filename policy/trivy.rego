package main

import rego.v1

deny contains msg if {
  some result in input.Results
  some vuln in result.Vulnerabilities
  sev := upper(vuln.Severity)
  sev == "CRITICAL"
  not is_fixed(vuln)
  msg := sprintf("Unfixed CRITICAL vulnerability found: %s in %s", [vuln.VulnerabilityID, result.Target])
}

deny contains msg if {
  some result in input.Results
  some vuln in result.Vulnerabilities
  sev := upper(vuln.Severity)
  sev == "HIGH"
  not is_fixed(vuln)
  msg := sprintf("Unfixed HIGH vulnerability found: %s in %s", [vuln.VulnerabilityID, result.Target])
}

is_fixed(vuln) if {
  fix := object.get(vuln, "FixedVersion", "")
  fix != ""
}