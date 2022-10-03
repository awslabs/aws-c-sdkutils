/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_SDKUTILS_ENDPOINTS_EVAL_UTIL_H
#define AWS_SDKUTILS_ENDPOINTS_EVAL_UTIL_H

#include <aws/sdkutils/sdkutils.h>

struct aws_string;

struct aws_byte_cursor aws_byte_cursor_from_substring(const struct aws_string *src, size_t start, size_t end);

/*
* Determine whether host cursor is IPv4 string.
*/
AWS_SDKUTILS_API bool aws_is_ipv4(struct aws_allocator *allocator, struct aws_byte_cursor host);

/*
* Determine whether host cursor is IPv6 string.
* Supports checking for uri encoded strings and scoped literals.
*/
AWS_SDKUTILS_API bool aws_is_ipv6(struct aws_allocator *allocator, struct aws_byte_cursor host, bool is_uri_encoded);

#endif /* AWS_SDKUTILS_ENDPOINTS_EVAL_UTIL_H */
