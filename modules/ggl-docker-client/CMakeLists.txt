# aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

ggl_init_module(
  ggl-docker-client
  LIBS ggl-sdk
       ggl-exec
       core-bus-gg-config
       ggl-http
       core-bus
       ggl-recipe
       ggl-uri)
