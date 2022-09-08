/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_SDKUTILS_ENDPOINTS_RULESET_H
#define AWS_SDKUTILS_ENDPOINTS_RULESET_H

#include <aws/common/byte_buf.h>
#include <aws/sdkutils/sdkutils.h>

struct aws_endpoints_ruleset;
struct aws_endpoints_parameter;
struct aws_hash_table;

enum aws_endpoints_parameter_value_type { AWS_ENDPOINTS_PARAMETER_STRING, AWS_ENDPOINTS_PARAMETER_BOOLEAN };

AWS_EXTERN_C_BEGIN

/*
******************************
* Parameter
******************************
*/

/*
 * Value type of parameter.
 */
AWS_SDKUTILS_API enum aws_endpoints_parameter_value_type aws_endpoints_parameter_get_value_type(
    const struct aws_endpoints_parameter *parameter);

/*
 * Parameter to built-in mapping.
 */
AWS_SDKUTILS_API const struct aws_string *aws_endpoints_parameter_get_built_in(
    const struct aws_endpoints_parameter *parameter);

/*
 * Default string value. Returns AWS_OP_ERR if parameter is not a string.
 */
AWS_SDKUTILS_API int aws_endpoints_parameter_get_default_string(
    const struct aws_endpoints_parameter *parameter,
    struct aws_string **out_string);

/*
 * Default boolean value. Returns AWS_OP_ERR if parameter is not a boolean.
 */
AWS_SDKUTILS_API int aws_endpoints_parameter_get_default_boolean(
    const struct aws_endpoints_parameter *parameter,
    bool *out_bool);

/*
 * Whether parameter is required.
 */
AWS_SDKUTILS_API bool aws_endpoints_parameter_get_is_required(const struct aws_endpoints_parameter *parameter);

/*
 * Parameter documentation.
 */
AWS_SDKUTILS_API const struct aws_string *aws_endpoints_parameter_get_documentation(
    const struct aws_endpoints_parameter *parameter);

/*
 * Whether parameter is deprecated.
 */
AWS_SDKUTILS_API bool aws_endpoints_parameters_get_is_deprecated(const struct aws_endpoints_parameter *parameter);

/*
 * Deprecation message. Null if parameter is not deprecated.
 */
AWS_SDKUTILS_API const struct aws_string *aws_endpoints_parameter_get_deprecated_message(
    const struct aws_endpoints_parameter *parameter);

/*
 * Deprecated since. Null if parameter is not deprecated.
 */
AWS_SDKUTILS_API const struct aws_string *aws_endpoints_parameter_get_deprecated_since(
    const struct aws_endpoints_parameter *parameter);

/*
******************************
* Ruleset
******************************
*/

/*
 * Create new endpoint from a json string.
 * In cases of failure NULL is returned and last error is set.
 */
AWS_SDKUTILS_API
struct aws_endpoints_ruleset *aws_endpoints_ruleset_new_from_string(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *ruleset_cur);

/*
 * Increment ref count
 */
AWS_SDKUTILS_API void aws_endpoints_ruleset_acquire(struct aws_endpoints_ruleset *ruleset);

/*
 * Decrement ref count
 */
AWS_SDKUTILS_API void aws_endpoints_ruleset_release(struct aws_endpoints_ruleset *ruleset);

/*
 * Get ruleset parameters.
 */
AWS_SDKUTILS_API const struct aws_hash_table *aws_endpoints_ruleset_get_parameters(
    struct aws_endpoints_ruleset *ruleset);

/*
 * Ruleset version.
 */
AWS_SDKUTILS_API const struct aws_string *aws_endpoints_ruleset_get_version(struct aws_endpoints_ruleset *ruleset);

/*
 * Ruleset service id.
 */
AWS_SDKUTILS_API const struct aws_string *aws_endpoints_ruleset_get_service_id(struct aws_endpoints_ruleset *ruleset);

AWS_EXTERN_C_END

#endif /* AWS_SDKUTILS_ENDPOINTS_RULESET_H */
