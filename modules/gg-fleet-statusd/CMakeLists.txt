# aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

ggl_init_module(
  gg-fleet-statusd
  LIBS ggl-sdk
       ggl-common
       core-bus
       core-bus-gghealthd
       core-bus-gg-config
       core-bus-aws-iot-mqtt
       ggl-constants)
