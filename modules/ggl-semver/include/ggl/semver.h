// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef GGL_SEMVER_H
#define GGL_SEMVER_H

#include <gg/types.h>
#include <stdbool.h>

/// Returns true if `version` satisfies every space-separated requirement in
/// `requirements_range`. Build metadata (a `+` suffix) is ignored when
/// determining precedence, on both the version and the requirement side, per
/// SemVer 2.0.0 section 10, so `2.6.0+abc123` satisfies `=2.6.0`.
bool is_in_range(GgBuffer version, GgBuffer requirements_range);

/// Returns true if `version` is a well-formed Semantic Versioning 2.0.0
/// string: `<major>.<minor>.<patch>[-<pre-release>][+<build>]`. Major, minor,
/// and patch are non-negative integers without leading zeros; pre-release and
/// build are dot-separated `[0-9A-Za-z-]` identifiers (non-empty, and
/// numeric pre-release identifiers carry no leading zeros).
bool is_valid_semver(GgBuffer version);

#endif
