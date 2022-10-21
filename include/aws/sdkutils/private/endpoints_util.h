/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_SDKUTILS_ENDPOINTS_EVAL_UTIL_H
#define AWS_SDKUTILS_ENDPOINTS_EVAL_UTIL_H

#include <aws/sdkutils/sdkutils.h>

struct aws_string;
struct aws_byte_buf;
struct aws_json_value;

/*
 * Replace escaped chars within endpoints templated strings.
 * Basically replaces {{ with { and }} with }.
 * Note: this function does not care about existence of { or } and will
 * leave them as is.
 */
AWS_SDKUTILS_API int aws_templated_string_replace_escaped(
    struct aws_allocator *allocator,
    struct aws_byte_cursor str,
    struct aws_byte_buf *out_buf);

/*
 * Replace escaped chars within endpoints templated strings embedded into json.
 * Basically replaces {{ with { and }} with }.
 * Note: this function does not care about existence of { or } and will
 * leave them as is.
 */
AWS_SDKUTILS_API int aws_json_templated_strings_replace_escaped(
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
 * Returns cursor indicating which partition region maps to or empty cursor if
 * region cannot be mapped.
 */
AWS_SDKUTILS_API struct aws_byte_cursor aws_map_region_to_partition(struct aws_byte_cursor region);

AWS_SDKUTILS_API int aws_byte_buf_init_from_normalized_uri_path(
    struct aws_allocator *allocator,
    struct aws_byte_cursor path,
    struct aws_byte_buf *out_normalized_path);

AWS_SDKUTILS_API struct aws_string *aws_string_new_from_json(
    struct aws_allocator *allocator,
    const struct aws_json_value *value);

AWS_SDKUTILS_API bool aws_endpoints_byte_cursor_eq(const void *a, const void *b);

/*
 * Helpers to do deep clean up of array list.
 * TODO: move to aws-c-common?
 */
typedef void(aws_array_callback_clean_up_fn)(void *value);
AWS_SDKUTILS_API void aws_array_list_deep_clean_up(
    struct aws_array_list *array,
    aws_array_callback_clean_up_fn on_clean_up_element);

typedef struct aws_string *(aws_endpoints_template_resolve_fn)(struct aws_byte_cursor template, void *user_data);
AWS_SDKUTILS_API int aws_byte_buf_init_from_resolved_templated_string(
    struct aws_allocator *allocator,
    struct aws_byte_buf *out_buf,
    struct aws_byte_cursor string,
    aws_endpoints_template_resolve_fn resolve_callback,
    void *user_data,
    bool is_json);

AWS_SDKUTILS_API int aws_path_through_json(
    struct aws_allocator *allocator,
    const struct aws_json_value *root,
    struct aws_byte_cursor path,
    const struct aws_json_value **out_value);
#endif /* AWS_SDKUTILS_ENDPOINTS_EVAL_UTIL_H */
