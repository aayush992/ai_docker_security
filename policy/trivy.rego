package main

import rego.v1

deny contains msg if {
  some result in input.Results
  some vuln in result.Vulnerabilities
  sev := upper(object.get(vuln, "Severity", "UNKNOWN"))
  sev == "CRITICAL"
  fix := trim(object.get(vuln, "FixedVersion", ""))
  fix != ""
  msg := sprintf("Fixable CRITICAL vulnerability found: %s in %s (fixed version: %s)", [vuln.VulnerabilityID, result.Target, fix])
}

deny contains msg if {
  some result in input.Results
  some vuln in result.Vulnerabilities
  sev := upper(object.get(vuln, "Severity", "UNKNOWN"))
  sev == "HIGH"
  fix := trim(object.get(vuln, "FixedVersion", ""))
  fix != ""
  msg := sprintf("Fixable HIGH vulnerability found: %s in %s (fixed version: %s)", [vuln.VulnerabilityID, result.Target, fix])
}