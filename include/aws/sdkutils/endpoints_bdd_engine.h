/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_SDKUTILS_ENDPOINTS_BDD_ENGINE_H
#define AWS_SDKUTILS_ENDPOINTS_BDD_ENGINE_H

#include <aws/common/byte_buf.h>
#include <aws/sdkutils/sdkutils.h>

AWS_PUSH_SANE_WARNING_LEVEL

struct aws_endpoints_bdd_engine;
struct aws_partitions_config;
struct aws_endpoints_request_context;
struct aws_endpoints_resolved_endpoint;

AWS_EXTERN_C_BEGIN

/**
 * Create a BDD engine from bytecode.
 *
 * @param allocator Memory allocator
 * @param bytecode Bytecode buffer
 * @param partitions_config Partition configuration (acquired by engine)
 * @return New BDD engine or NULL on error
 */
AWS_SDKUTILS_API struct aws_endpoints_bdd_engine *aws_endpoints_bdd_engine_new_from_bytecode(
    struct aws_allocator *allocator,
    struct aws_byte_cursor bytecode,
    struct aws_partitions_config *partitions_config);

/**
 * Acquire a reference to the BDD engine.
 *
 * @param engine BDD engine
 * @return The same engine pointer
 */
AWS_SDKUTILS_API struct aws_endpoints_bdd_engine *aws_endpoints_bdd_engine_acquire(
    struct aws_endpoints_bdd_engine *engine);

/**
 * Release a reference to the BDD engine. Destroys the engine when ref count reaches zero.
 *
 * @param engine BDD engine
 * @return NULL
 */
AWS_SDKUTILS_API struct aws_endpoints_bdd_engine *aws_endpoints_bdd_engine_release(
    struct aws_endpoints_bdd_engine *engine);

/**
 * Resolve an endpoint using the BDD engine.
 *
 * @param engine BDD engine
 * @param context Request context with parameter values
 * @param out_resolved_endpoint Output resolved endpoint or error
 * @return AWS_OP_SUCCESS on success, AWS_OP_ERR on failure
 */
AWS_SDKUTILS_API int aws_endpoints_bdd_engine_resolve(
    struct aws_endpoints_bdd_engine *engine,
    const struct aws_endpoints_request_context *context,
    struct aws_endpoints_resolved_endpoint **out_resolved_endpoint);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_SDKUTILS_ENDPOINTS_BDD_ENGINE_H */
