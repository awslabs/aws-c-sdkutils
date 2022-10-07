/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_SDKUTILS_ENDPOINTS_EVAL_UTIL_H
#define AWS_SDKUTILS_ENDPOINTS_EVAL_UTIL_H

#include <aws/sdkutils/sdkutils.h>

struct aws_string;
struct aws_byte_buf;

struct aws_byte_cursor aws_byte_cursor_from_substring(const struct aws_string *src, size_t start, size_t end);

/*
 * Replaced escaped chars within endpoints templated strings.
 * Basically replaces {{ with { and }} with }.
 * Note: this function does not care about existence of since { or } and will
 * leave them as is.
 */
AWS_SDKUTILS_API int aws_templated_string_strip_replace_escaped(
    struct aws_allocator *allocator,
    struct aws_byte_cursor str,
    struct aws_byte_buf *out_buf);

/*
 * Determine whether host cursor is IPv4 string.
 */
AWS_SDKUTILS_API bool aws_is_ipv4(struct aws_byte_cursor host);

/*
 * Determine whether host cursor is IPv6 string.
 * Supports checking for uri encoded strings and scoped literals.
 */
AWS_SDKUTILS_API bool aws_is_ipv6(struct aws_byte_cursor host, bool is_uri_encoded);

/*
 * Determine whether label is a valid host label.
 */
AWS_SDKUTILS_API bool aws_is_valid_host_label(struct aws_byte_cursor label, bool allow_subdomains);

/*
 * Determines partition from region name.
 * Note: this basically implements regex-less alternative to regexes specified in
 * partitions file.
 */
AWS_SDKUTILS_API struct aws_byte_cursor aws_map_region_to_partition(struct aws_byte_cursor region);

#endif /* AWS_SDKUTILS_ENDPOINTS_EVAL_UTIL_H */
