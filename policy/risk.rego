package main

import rego.v1

deny contains msg if {
  object.get(input, "risk", 0.0) > 0.65
  msg := sprintf("Risk score too high: %v (max allowed: 0.65)", [input.risk])
}