package main

import rego.v1

deny contains msg if {
  some i
  input[i].Cmd == "from"
  image := lower(input[i].Value[0])
  endswith(image, ":latest")
  msg := sprintf("Dockerfile uses forbidden latest tag: %s", [image])
}

deny contains msg if {
  some i
  input[i].Cmd == "from"
  image := lower(input[i].Value[0])
  not contains(image, ":")
  msg := sprintf("Dockerfile base image has no explicit tag: %s", [image])
}