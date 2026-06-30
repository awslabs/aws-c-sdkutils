/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/sdkutils/endpoints_bdd_engine.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>

static int s_copy_context_to_state(
    const struct aws_endpoints_request_context *context,
    struct aws_endpoints_bdd_engine_state *state) {

    struct aws_bdd_scope *scope_impl = &state->scope_impl;

    for (struct aws_hash_iter iter = aws_hash_iter_begin(&context->values); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {

        struct aws_endpoints_scope_value *context_value = (struct aws_endpoints_scope_value *)iter.element.value;
        struct aws_hash_element *element = NULL;
        aws_hash_table_find(&state->engine->register_map, &context_value->name.cur, &element);

        if (element == NULL) {
            AWS_LOGF_ERROR(
                AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE,
                "Received a context variable not present in parameters: " PRInSTR,
                AWS_BYTE_CURSOR_PRI(context_value->name.cur));
            return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_INIT_FAILED);
        }

        size_t idx = (size_t)element->value - 1;

        struct aws_endpoints_scope_value *scope_value = &scope_impl->values[idx];
        scope_value->allocator = NULL;
        scope_value->name = aws_endpoints_non_owning_cursor_create(context_value->name.cur);
        scope_value->value = context_value->value;
        scope_value->value.is_ref = true;
    }

    return AWS_OP_SUCCESS;
}

struct aws_endpoints_scope_value *s_bdd_scope_find_fn(void *scope_impl, struct aws_endpoints_reference ref) {
    struct aws_bdd_scope *bdd_scope = scope_impl;

    struct aws_endpoints_scope_value *ret = NULL;

    if (ref.bdd_ref_idx == 0) {
        struct aws_hash_element *element = NULL;
        aws_hash_table_find(&bdd_scope->engine->register_map, &ref.name, &element);
        if (element == NULL) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Could not find reference in implementation");
            aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_INIT_FAILED);
            return NULL;
        }

        size_t reg_idx = (size_t)element->value;
        ref.bdd_ref_idx = reg_idx;
    }

    ret = &bdd_scope->values[ref.bdd_ref_idx - 1];

    if (ret->value.type == AWS_ENDPOINTS_VALUE_UNSET) {
        return NULL;
    }

    return ret;
}

static int s_init_state(
    const struct aws_endpoints_request_context *context,
    struct aws_endpoints_bdd_engine *engine,
    struct aws_endpoints_bdd_engine_state *state) {
    AWS_PRECONDITION(context);
    AWS_PRECONDITION(engine);
    AWS_PRECONDITION(state);

    state->scope.partitions = engine->partitions_config;
    state->scope.scope_impl = &state->scope_impl;
    state->scope.find = s_bdd_scope_find_fn;
    state->engine = engine;
    state->scope_impl.engine = engine;

    aws_array_list_init_static_from_initialized(
        &state->scope.expr_index, engine->expr_ptr, engine->expr_len, sizeof(struct aws_endpoints_expr));

    if (s_copy_context_to_state(context, state)) {
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_INIT_FAILED);
    }

    /* Add defaults to the top level scope. */
    for (size_t i = 0; i < aws_array_list_length(&engine->parameters); ++i) {
        struct aws_endpoints_parameter *value = NULL;
        aws_array_list_get_at_ptr(&engine->parameters, (void **)&value, i);

        /* value should always be present in the register map since we load parameters into the map */
        if (value->param_idx == 0) {
            AWS_LOGF_ERROR(
                AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE,
                "Value not present in register map: " PRInSTR,
                AWS_BYTE_CURSOR_PRI(value->name));
            return AWS_OP_ERR;
        }

        /* Skip non-required values, since they cannot have default values. */
        if (!value->is_required) {
            continue;
        }

        size_t idx = value->param_idx - 1;

        if (state->scope_impl.values[idx].value.type == AWS_ENDPOINTS_VALUE_UNSET) {
            if (!value->has_default_value) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "No value or default for required parameter.");
                return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_INIT_FAILED);
            }

            struct aws_endpoints_scope_value *scope_value = &state->scope_impl.values[idx];

            switch (value->type) {
                case AWS_ENDPOINTS_PARAMETER_STRING:
                case AWS_ENDPOINTS_PARAMETER_BOOLEAN:
                case AWS_ENDPOINTS_PARAMETER_STRING_ARRAY:
                    scope_value->value = value->default_value;
                    scope_value->value.is_ref = true;
                    scope_value->name = aws_endpoints_non_owning_cursor_create(value->name);
                    break;
                default:
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Unexpected parameter type.");
                    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_INIT_FAILED);
            }
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_resolve_one_condition(
    struct aws_allocator *allocator,
    struct aws_endpoints_condition *condition,
    struct aws_endpoints_bdd_engine_state *state,
    bool *out_is_truthy) {

    struct aws_endpoints_value val;
    if (aws_endpoints_resolve_expr(allocator, condition->expr_ref, &state->scope, &val)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve expr.");
        goto on_error;
    }

    *out_is_truthy = aws_endpoints_is_value_truthy(&val);

    if (condition->assign.len > 0) {
        struct aws_bdd_scope *scope_impl = &state->scope_impl;
        struct aws_endpoints_scope_value *scope_value = &scope_impl->values[condition->assign_idx - 1];

        scope_value->allocator = NULL;
        scope_value->name = aws_endpoints_non_owning_cursor_create(condition->assign);
        scope_value->value = val;
    } else {
        /* Otherwise clean up temp value */
        aws_endpoints_value_clean_up(&val);
    }

    return AWS_OP_SUCCESS;

on_error:
    *out_is_truthy = false;
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
}

static void s_state_clean_up(struct aws_endpoints_bdd_engine_state *state) {
    AWS_PRECONDITION(state);

    for (size_t i = 0; i < s_max_regs; ++i) {
        aws_endpoints_value_clean_up(&state->scope_impl.values[i].value);
    }
}

static const int32_t s_result_bound = 100000000;

int aws_endpoints_bdd_engine_resolve(
    struct aws_endpoints_bdd_engine *engine,
    const struct aws_endpoints_request_context *context,
    struct aws_endpoints_resolved_endpoint **out_resolved_endpoint) {

    int result = AWS_OP_SUCCESS;
    struct aws_endpoints_bdd_engine_state state;
    AWS_ZERO_STRUCT(state);
    if (s_init_state(context, engine, &state)) {
        result = AWS_OP_ERR;
        goto on_done;
    }

    int32_t current_ref = engine->root_ref;

    while (current_ref != 1 && current_ref != -1 && /* terminal no match */
           current_ref < s_result_bound) {

        bool is_complement = current_ref < 0;
        int32_t node_index = (is_complement ? -current_ref : current_ref) - 1;

        struct aws_endpoints_bdd_node *node;
        if (aws_array_list_get_at_ptr(&engine->nodes, (void **)&node, node_index)) {
            result = aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
            goto on_done;
        }

        int32_t condition_index = node->condition_index;
        struct aws_endpoints_condition *current_condition;

        if (aws_array_list_get_at_ptr(&engine->conditions, (void **)&current_condition, condition_index)) {
            result = aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
            goto on_done;
        }

        bool is_truthy = false;
        if (s_resolve_one_condition(engine->allocator, current_condition, &state, &is_truthy)) {
            result = aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
            goto on_done;
        }

        if (is_complement ^ is_truthy) {
            current_ref = node->high_ref;
        } else {
            current_ref = node->low_ref;
        }
    }

    /* eval terminal result */
    if (current_ref == 1 || current_ref == -1) { /* no match */
        result = aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RULESET_EXHAUSTED);
        goto on_done;
    }

    if (current_ref < s_result_bound) {
        result = aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
        goto on_done;
    }

    int32_t result_idx = (current_ref - s_result_bound);
    struct aws_endpoints_bdd_result eval_result;
    if (aws_array_list_get_at(&engine->results, &eval_result, result_idx)) {
        result = aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
        goto on_done;
    }

    if (eval_result.type == AWS_ENDPOINTS_RESOLVED_ENDPOINT) {
        struct aws_endpoints_resolved_endpoint *endpoint = aws_endpoints_resolved_endpoint_new(engine->allocator);
        endpoint->type = AWS_ENDPOINTS_RESOLVED_ENDPOINT;

        struct aws_endpoints_value val;
        if (aws_endpoints_resolve_expr(engine->allocator, eval_result.data.endpoint.url_expr_ref, &state.scope, &val) ||
            val.type != AWS_ENDPOINTS_VALUE_STRING ||
            aws_byte_buf_init_copy_from_cursor(
                &endpoint->r.endpoint.url, engine->allocator, val.v.owning_cursor_string.cur)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve templated url.");
            result = AWS_OP_ERR;
            aws_endpoints_resolved_endpoint_release(endpoint);
            goto on_done;
        }

        aws_endpoints_value_clean_up(&val);

        struct resolve_template_callback_data data = {.allocator = engine->allocator, .scope = &state.scope};

        if (eval_result.data.endpoint.properties.len > 0 &&
            aws_byte_buf_init_from_resolved_templated_string(
                engine->allocator,
                &endpoint->r.endpoint.properties,
                aws_byte_cursor_from_buf(&eval_result.data.endpoint.properties),
                aws_endpoints_resolve_template,
                &data,
                true)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve templated properties.");
            result = AWS_OP_ERR;
            aws_endpoints_resolved_endpoint_release(endpoint);
            goto on_done;
        }

        if (aws_endpoints_resolve_headers(
                engine->allocator, &state.scope, &eval_result.data.endpoint.headers, &endpoint->r.endpoint.headers)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve templated headers.");
            result = AWS_OP_ERR;
            aws_endpoints_resolved_endpoint_release(endpoint);
            goto on_done;
        }

        *out_resolved_endpoint = endpoint;
        goto on_done;
    } else if (eval_result.type == AWS_ENDPOINTS_RESOLVED_ERROR) {
        struct aws_endpoints_resolved_endpoint *error = aws_endpoints_resolved_endpoint_new(engine->allocator);
        error->type = AWS_ENDPOINTS_RESOLVED_ERROR;

        struct aws_endpoints_value val;
        if (aws_endpoints_resolve_expr(engine->allocator, eval_result.data.error.error_expr_ref, &state.scope, &val) ||
            val.type != AWS_ENDPOINTS_VALUE_STRING ||
            aws_byte_buf_init_copy_from_cursor(&error->r.error, engine->allocator, val.v.owning_cursor_string.cur)) {
            aws_endpoints_value_clean_up(&val);
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve templated url.");
            result = AWS_OP_ERR;
            aws_endpoints_resolved_endpoint_release(error);
            goto on_done;
        }

        aws_endpoints_value_clean_up(&val);
        *out_resolved_endpoint = error;
        goto on_done;
    } else {
        result = aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
        goto on_done;
    }

on_done:
    s_state_clean_up(&state);
    return result;
}
