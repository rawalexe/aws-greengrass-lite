// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "bus_server.h"
#include "deployment_queue.h"
#include <ggl/core_bus/server.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <ggl/object.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static void create_local_deployment(void *ctx, GglMap params, uint32_t handle) {
    (void) ctx;

    GGL_LOGT(
        "ggdeploymentd", "Received create_local_deployment from core bus."
    );

    GglBuffer id = GGL_BUF((uint8_t[36]) { 0 });

    GglError ret = ggl_deployment_enqueue(params, &id);
    if (ret != GGL_ERR_OK) {
        ggl_return_err(handle, ret);
        return;
    }

    ggl_respond(handle, GGL_OBJ_MAP({ GGL_STR("deployment_id"), GGL_OBJ(id) }));
}

void ggdeploymentd_start_server(void) {
    GGL_LOGI("ggdeploymentd", "Starting ggdeploymentd core bus server.");

    GglRpcMethodDesc handlers[] = { { GGL_STR("create_local_deployment"),
                                      false,
                                      create_local_deployment,
                                      NULL } };
    size_t handlers_len = sizeof(handlers) / sizeof(handlers[0]);

    GglError ret
        = ggl_listen(GGL_STR("/aws/ggl/ggdeploymentd"), handlers, handlers_len);

    GGL_LOGE("ggdeploymentd", "Exiting with error %u.", (unsigned) ret);
}
