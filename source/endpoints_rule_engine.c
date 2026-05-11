/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/byte_buf.h>
#include <aws/common/json.h>
#include <aws/common/macros.h>
#include <aws/common/string.h>
#include <aws/sdkutils/partitions.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>
#include <aws/sdkutils/private/endpoints_util.h>
#include <inttypes.h>
#include <stdio.h>

/* TODO: checking for unknown enum values is annoying and is brittle. compile
time assert on enum size or members would make it a lot simpler. */

/*
 * How rule resolution works.
 * Note: read comments in endpoint_types_impl.h first to understand type system.
 *
 * Initial scope is created from parameters defined in request context and
 * default values defined in ruleset (s_init_top_level_scope). Validation that
 * all required parameters have values is done at this point as well.
 *
 * Rules are then resolved sequentially against scope.
 * First list of conditions associated with the rule is resolved
 * (s_resolve_conditions). Final result of conditions resolution is an AND of
 * truthiness of resolved values (as defined in is_value_truthy) for each
 * condition. If resolution is true then rule is selected.
 * - For endpoint and error rules that means terminal state is reached and rule
 *   data is returned
 * - For tree rule, the engine starts resolving rules associated with tree rule.
 *   Note: tree rules are terminal and once engine jumps into tree rule
 *   resolution there is no way to jump back out.
 *
 * Conditions can add values to scope. Those values are valid for the duration of
 * rule resolution. Note: for tree rules, any values added in tree conditions are
 * valid for all rules within the tree.
 * Scope can be though of as a 'leveled' structure. Top level or 0 level
 * represents all values from context and defaults. Levels 1 and up represent
 * values added by rules. Ex. if we start at level 0, all values added by rule
 * can be though of as level 1.
 * Since tree rule cannot be exited from, engine is simplified by making all
 * values in scope top level whenever tree is jumped into. So in practice engine
 * goes back between top level and first level as resolving rules. If that
 * changes in future, scope can add explicit level number and cleanup only values
 * at that level when going to next rule.
 *
 * Overall flow is as follows:
 * - Start with any values provided in context as scope
 * - Add any default values provided in ruleset and validate all required
 *   params are specified.
 * - Iterate through rules and resolve each rule:
 * -- resolve conditions with side effects
 * -- if conditions are truthy return rule result
 * -- if conditions are truthy and rule is tree, jump down a level and
 *   restart resolution with tree rules
 * -- if conditions are falsy, rollback level and go to next rule
 * - if no rules match, resolution fails with exhausted error.
 */

static void s_scope_value_destroy_cb(void *data) {
    struct aws_endpoints_scope_value *value = data;
    aws_endpoints_scope_value_destroy(value);
}

static int s_deep_copy_context_to_scope(
    struct aws_allocator *allocator,
    const struct aws_endpoints_request_context *context,
    struct aws_endpoints_resolution_scope *scope) {

    struct aws_endpoints_scope_value *new_value = NULL;

    for (struct aws_hash_iter iter = aws_hash_iter_begin(&context->values); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {

        struct aws_endpoints_scope_value *context_value = (struct aws_endpoints_scope_value *)iter.element.value;

        new_value = aws_endpoints_scope_value_new(allocator, context_value->name.cur);
        if (aws_endpoints_deep_copy_parameter_value(allocator, &context_value->value, &new_value->value)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to deep copy value.");
            goto on_error;
        }

        if (aws_hash_table_put(&scope->values, &new_value->name.cur, new_value, NULL)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to add deep copy to scope.");
            goto on_error;
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_scope_value_destroy(new_value);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_INIT_FAILED);
}

static int s_init_top_level_scope(
    struct aws_allocator *allocator,
    const struct aws_endpoints_request_context *context,
    const struct aws_endpoints_ruleset *ruleset,
    const struct aws_partitions_config *partitions,
    struct aws_endpoints_resolution_state *state) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(context);
    AWS_PRECONDITION(ruleset);
    AWS_PRECONDITION(scope);

    state->rule_idx = 0;
    state->rules = &ruleset->rules;
    state->scope.partitions = partitions;
    state->scope.expr_index = ruleset->exprs;

    if (aws_hash_table_init(
            &state->scope.values,
            allocator,
            0,
            aws_hash_byte_cursor_ptr,
            aws_endpoints_byte_cursor_eq,
            NULL,
            s_scope_value_destroy_cb)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to init request context values.");
        goto on_error;
    }

    if (s_deep_copy_context_to_scope(allocator, context, &state->scope)) {
        goto on_error;
    }

    if (aws_array_list_init_dynamic(&state->added_keys, allocator, 10, sizeof(struct aws_byte_cursor))) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to init added keys.");
        goto on_error;
    }

    /* Add defaults to the top level scope. */
    for (struct aws_hash_iter iter = aws_hash_iter_begin(&ruleset->parameters); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        const struct aws_byte_cursor key = *(const struct aws_byte_cursor *)iter.element.key;
        struct aws_endpoints_parameter *value = (struct aws_endpoints_parameter *)iter.element.value;

        /* Skip non-required values, since they cannot have default values. */
        if (!value->is_required) {
            continue;
        }

        struct aws_hash_element *existing = NULL;
        if (aws_hash_table_find(&state->scope.values, &key, &existing)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to init request context values.");
            return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_INIT_FAILED);
        }

        if (existing == NULL) {
            if (!value->has_default_value) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "No value or default for required parameter.");
                goto on_error;
            }

            struct aws_endpoints_scope_value *val = aws_endpoints_scope_value_new(allocator, key);
            AWS_ASSERT(val);

            switch (value->type) {
                case AWS_ENDPOINTS_PARAMETER_STRING:
                case AWS_ENDPOINTS_PARAMETER_BOOLEAN:
                case AWS_ENDPOINTS_PARAMETER_STRING_ARRAY:
                    val->value = value->default_value;
                    val->value.is_ref = true;
                    break;
                default:
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Unexpected parameter type.");
                    aws_endpoints_scope_value_destroy(val);
                    goto on_error;
            }

            if (aws_hash_table_put(&state->scope.values, &val->name.cur, val, NULL)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to add value to top level scope.");
                aws_endpoints_scope_value_destroy(val);
                goto on_error;
            }
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_INIT_FAILED);
}

static void s_state_clean_up(struct aws_endpoints_resolution_state *state) {
    AWS_PRECONDITION(scope);

    aws_hash_table_clean_up(&state->scope.values);
    aws_array_list_clean_up(&state->added_keys);
}

/*
******************************
* Expr/String resolve
******************************
*/

static int s_resolve_one_condition(
    struct aws_allocator *allocator,
    struct aws_endpoints_condition *condition,
    struct aws_endpoints_resolution_state *state,
    bool *out_is_truthy) {

    struct aws_endpoints_scope_value *scope_value = NULL;

    struct aws_endpoints_value val;
    if (aws_endpoints_resolve_expr(allocator, condition->expr_ref, &state->scope, &val)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve expr.");
        goto on_error;
    }

    *out_is_truthy = aws_endpoints_is_value_truthy(&val);

    /* Note: assigning value is skipped if condition is falsy, since nothing can
    use it and that avoids adding value and then removing it from scope right away. */
    if (*out_is_truthy && condition->assign.len > 0) {
        /* If condition assigns a value, push it to scope and let scope
        handle value memory. */
        scope_value = aws_endpoints_scope_value_new(allocator, condition->assign);
        scope_value->value = val;

        if (aws_array_list_push_back(&state->added_keys, &scope_value->name.cur)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to update key at given scope.");
            goto on_error;
        }

        int was_created = 1;
        if (aws_hash_table_put(&state->scope.values, &scope_value->name.cur, scope_value, &was_created)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to set assigned variable.");
            goto on_error;
        }

        /* Shadowing existing values is prohibited. */
        if (!was_created) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Assigned variable shadows existing one.");
            goto on_error;
        }
    } else {
        /* Otherwise clean up temp value */
        aws_endpoints_value_clean_up(&val);
    }

    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_scope_value_destroy(scope_value);
    /* Only cleanup value if mem ownership was not transferred to scope value. */
    if (scope_value == NULL) {
        aws_endpoints_value_clean_up(&val);
    }

    *out_is_truthy = false;
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
}

static int s_resolve_conditions(
    struct aws_allocator *allocator,
    const struct aws_array_list *conditions,
    struct aws_endpoints_resolution_state *state,
    bool *out_is_truthy) {

    /* Note: spec defines empty conditions list as truthy. */
    *out_is_truthy = true;

    for (size_t idx = 0; idx < aws_array_list_length(conditions); ++idx) {
        struct aws_endpoints_condition *condition = NULL;
        if (aws_array_list_get_at_ptr(conditions, (void **)&condition, idx)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to retrieve condition.");
            goto on_error;
        }

        if (s_resolve_one_condition(allocator, condition, state, out_is_truthy)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve condition.");
            goto on_error;
        }

        /* truthiness of all conditions is an AND of truthiness for each condition,
            hence first false one short circuits resolution */
        if (!*out_is_truthy) {
            break;
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    *out_is_truthy = false;
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
}

int aws_endpoints_path_through_array(
    struct aws_allocator *allocator,
    struct aws_endpoints_resolution_scope *scope,
    struct aws_endpoints_value *value,
    struct aws_byte_cursor path_cur,
    struct aws_endpoints_value *out_value) {
    (void)allocator;
    (void)scope;

    AWS_PRECONDITION(value->type == AWS_ENDPOINTS_VALUE_ARRAY);

    int64_t index;
    struct aws_byte_cursor split = {0};
    if ((!aws_byte_cursor_next_split(&path_cur, '[', &split) || split.len > 0) ||
        !aws_byte_cursor_next_split(&path_cur, ']', &split) || aws_byte_cursor_utf8_parse_i64(split, &index)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Could not parse index from template string.");
        goto on_error;
    }

    if (index >= aws_array_list_length(&value->v.array)) {
        out_value->type = AWS_ENDPOINTS_VALUE_NONE;
        return AWS_OP_SUCCESS;
    }

    if (index < 0) {
        index = aws_array_list_length(&value->v.array)  - index;
    }

    if (index < 0) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Unexpected negative index.");
        goto on_error;
    }

    struct aws_endpoints_value *val = NULL;
    if (aws_array_list_get_at_ptr(&value->v.array, (void **)&val, (size_t)index)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to index into resolved value");
        goto on_error;
    }

    *out_value = *val;
    out_value->is_ref = true;

    return AWS_OP_SUCCESS;

on_error:
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
}

int aws_endpoints_path_through_object(
    struct aws_allocator *allocator,
    struct aws_endpoints_value *value,
    struct aws_byte_cursor path_cur,
    struct aws_endpoints_value *out_value) {

    AWS_ZERO_STRUCT(*out_value);
    struct aws_json_value *root_node = NULL;

    struct aws_byte_cursor value_cur = value->type != AWS_ENDPOINTS_VALUE_STRING ? value->v.owning_cursor_string.cur
                                                                                 : value->v.owning_cursor_object.cur;

    root_node = aws_json_value_new_from_string(allocator, value_cur);
    const struct aws_json_value *result;
    if (aws_path_through_json(allocator, root_node, path_cur, &result)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to path through json.");
        goto on_error;
    }

    if (result == NULL) {
        out_value->type = AWS_ENDPOINTS_VALUE_NONE;
    } else if (aws_json_value_is_string(result)) {
        struct aws_byte_cursor final;
        if (aws_json_value_get_string(result, &final)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Could not parse string from node.");
            goto on_error;
        }

        out_value->type = AWS_ENDPOINTS_VALUE_STRING;
        out_value->v.owning_cursor_string = aws_endpoints_owning_cursor_from_cursor(allocator, final);
    } else if (aws_json_value_is_array(result) || aws_json_value_is_object(result)) {
        struct aws_byte_buf json_blob;
        aws_byte_buf_init(&json_blob, allocator, 0);

        if (aws_byte_buf_append_json_string(result, &json_blob)) {
            aws_byte_buf_clean_up(&json_blob);
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to extract properties.");
            goto on_error;
        }

        aws_byte_buf_clean_up(&json_blob);
        out_value->type = AWS_ENDPOINTS_VALUE_OBJECT;
        out_value->v.owning_cursor_object =
            aws_endpoints_owning_cursor_from_string(aws_string_new_from_buf(allocator, &json_blob));
    } else if (aws_json_value_is_boolean(result)) {
        if (aws_json_value_get_boolean(result, &out_value->v.boolean)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Could not parse boolean from node.");
            goto on_error;
        }

        out_value->type = AWS_ENDPOINTS_VALUE_BOOLEAN;
    } else if (aws_json_value_is_number(result)) {
        if (aws_json_value_get_number(result, &out_value->v.number)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Could not parse number from node.");
            goto on_error;
        }

        out_value->type = AWS_ENDPOINTS_VALUE_NUMBER;
    }

    aws_json_value_destroy(root_node);
    return AWS_OP_SUCCESS;

on_error:
    aws_json_value_destroy(root_node);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
}

/*
******************************
* Request Context
******************************
*/

static void s_endpoints_request_context_destroy(void *data) {
    if (data == NULL) {
        return;
    }

    struct aws_endpoints_request_context *context = data;
    aws_hash_table_clean_up(&context->values);

    aws_mem_release(context->allocator, context);
}

struct aws_endpoints_request_context *aws_endpoints_request_context_new(struct aws_allocator *allocator) {
    AWS_PRECONDITION(allocator);

    struct aws_endpoints_request_context *context =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_request_context));

    context->allocator = allocator;
    aws_ref_count_init(&context->ref_count, context, s_endpoints_request_context_destroy);

    if (aws_hash_table_init(
            &context->values,
            allocator,
            0,
            aws_hash_byte_cursor_ptr,
            aws_endpoints_byte_cursor_eq,
            NULL,
            s_scope_value_destroy_cb)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to init request context values.");
        goto on_error;
    }

    return context;

on_error:
    s_endpoints_request_context_destroy(context);
    return NULL;
}

struct aws_endpoints_request_context *aws_endpoints_request_context_acquire(
    struct aws_endpoints_request_context *request_context) {
    AWS_PRECONDITION(request_context);
    if (request_context) {
        aws_ref_count_acquire(&request_context->ref_count);
    }
    return request_context;
}

struct aws_endpoints_request_context *aws_endpoints_request_context_release(
    struct aws_endpoints_request_context *request_context) {
    if (request_context) {
        aws_ref_count_release(&request_context->ref_count);
    }
    return NULL;
}

int aws_endpoints_request_context_add_string(
    struct aws_allocator *allocator,
    struct aws_endpoints_request_context *context,
    struct aws_byte_cursor name,
    struct aws_byte_cursor value) {
    AWS_PRECONDITION(allocator);

    struct aws_endpoints_scope_value *val = aws_endpoints_scope_value_new(allocator, name);
    val->value.type = AWS_ENDPOINTS_VALUE_STRING;
    val->value.v.owning_cursor_string = aws_endpoints_owning_cursor_from_cursor(allocator, value);

    if (aws_hash_table_put(&context->values, &val->name.cur, val, NULL)) {
        aws_endpoints_scope_value_destroy(val);
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_INIT_FAILED);
    };

    return AWS_OP_SUCCESS;
}

int aws_endpoints_request_context_add_boolean(
    struct aws_allocator *allocator,
    struct aws_endpoints_request_context *context,
    struct aws_byte_cursor name,
    bool value) {
    AWS_PRECONDITION(allocator);

    struct aws_endpoints_scope_value *val = aws_endpoints_scope_value_new(allocator, name);
    val->value.type = AWS_ENDPOINTS_VALUE_BOOLEAN;
    val->value.v.boolean = value;

    if (aws_hash_table_put(&context->values, &val->name.cur, val, NULL)) {
        aws_endpoints_scope_value_destroy(val);
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_INIT_FAILED);
    };

    return AWS_OP_SUCCESS;
}

int aws_endpoints_request_context_add_string_array(
    struct aws_allocator *allocator,
    struct aws_endpoints_request_context *context,
    struct aws_byte_cursor name,
    const struct aws_byte_cursor *values,
    size_t len) {

    struct aws_endpoints_scope_value *val = aws_endpoints_scope_value_new(allocator, name);
    val->value.type = AWS_ENDPOINTS_VALUE_ARRAY;
    aws_array_list_init_dynamic(&val->value.v.array, allocator, len, sizeof(struct aws_endpoints_value));

    for (size_t i = 0; i < len; ++i) {
        struct aws_endpoints_value elem = {
            .is_ref = false,
            .type = AWS_ENDPOINTS_VALUE_STRING,
            .v.owning_cursor_object = aws_endpoints_owning_cursor_from_cursor(allocator, values[i])};

        aws_array_list_set_at(&val->value.v.array, &elem, i);
    }

    if (aws_hash_table_put(&context->values, &val->name.cur, val, NULL)) {
        aws_endpoints_scope_value_destroy(val);
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_INIT_FAILED);
    };

    return AWS_OP_SUCCESS;
}

/*
******************************
* Rule engine.
******************************
*/

struct aws_endpoints_resolved_endpoint *aws_endpoints_resolved_endpoint_acquire(
    struct aws_endpoints_resolved_endpoint *resolved_endpoint) {
    AWS_PRECONDITION(resolved_endpoint);
    if (resolved_endpoint) {
        aws_ref_count_acquire(&resolved_endpoint->ref_count);
    }
    return resolved_endpoint;
}

struct aws_endpoints_resolved_endpoint *aws_endpoints_resolved_endpoint_release(
    struct aws_endpoints_resolved_endpoint *resolved_endpoint) {
    if (resolved_endpoint) {
        aws_ref_count_release(&resolved_endpoint->ref_count);
    }
    return NULL;
}

enum aws_endpoints_resolved_endpoint_type aws_endpoints_resolved_endpoint_get_type(
    const struct aws_endpoints_resolved_endpoint *resolved_endpoint) {
    AWS_PRECONDITION(resolved_endpoint);
    return resolved_endpoint->type;
}

int aws_endpoints_resolved_endpoint_get_url(
    const struct aws_endpoints_resolved_endpoint *resolved_endpoint,
    struct aws_byte_cursor *out_url) {
    AWS_PRECONDITION(resolved_endpoint);
    AWS_PRECONDITION(out_url);
    if (resolved_endpoint->type != AWS_ENDPOINTS_RESOLVED_ENDPOINT) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    *out_url = aws_byte_cursor_from_buf(&resolved_endpoint->r.endpoint.url);
    return AWS_OP_SUCCESS;
}

int aws_endpoints_resolved_endpoint_get_properties(
    const struct aws_endpoints_resolved_endpoint *resolved_endpoint,
    struct aws_byte_cursor *out_properties) {
    AWS_PRECONDITION(resolved_endpoint);
    AWS_PRECONDITION(out_properties);
    if (resolved_endpoint->type != AWS_ENDPOINTS_RESOLVED_ENDPOINT) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    *out_properties = aws_byte_cursor_from_buf(&resolved_endpoint->r.endpoint.properties);
    return AWS_OP_SUCCESS;
}

int aws_endpoints_resolved_endpoint_get_headers(
    const struct aws_endpoints_resolved_endpoint *resolved_endpoint,
    const struct aws_hash_table **out_headers) {
    AWS_PRECONDITION(resolved_endpoint);
    AWS_PRECONDITION(out_headers);
    if (resolved_endpoint->type != AWS_ENDPOINTS_RESOLVED_ENDPOINT) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    *out_headers = &resolved_endpoint->r.endpoint.headers;
    return AWS_OP_SUCCESS;
}

int aws_endpoints_resolved_endpoint_get_error(
    const struct aws_endpoints_resolved_endpoint *resolved_endpoint,
    struct aws_byte_cursor *out_error) {
    AWS_PRECONDITION(resolved_endpoint);
    AWS_PRECONDITION(out_error);
    if (resolved_endpoint->type != AWS_ENDPOINTS_RESOLVED_ERROR) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    *out_error = aws_byte_cursor_from_buf(&resolved_endpoint->r.error);
    return AWS_OP_SUCCESS;
}

struct aws_endpoints_rule_engine {
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;

    struct aws_endpoints_ruleset *ruleset;
    struct aws_partitions_config *partitions_config;
};

static void s_endpoints_rule_engine_destroy(void *data) {
    if (data == NULL) {
        return;
    }

    struct aws_endpoints_rule_engine *engine = data;
    aws_endpoints_ruleset_release(engine->ruleset);
    aws_partitions_config_release(engine->partitions_config);

    aws_mem_release(engine->allocator, engine);
}

struct aws_endpoints_rule_engine *aws_endpoints_rule_engine_new(
    struct aws_allocator *allocator,
    struct aws_endpoints_ruleset *ruleset,
    struct aws_partitions_config *partitions_config) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(ruleset);

    struct aws_endpoints_rule_engine *engine = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_rule_engine));
    engine->allocator = allocator;
    engine->ruleset = ruleset;
    engine->partitions_config = partitions_config;

    aws_endpoints_ruleset_acquire(ruleset);
    aws_partitions_config_acquire(partitions_config);
    aws_ref_count_init(&engine->ref_count, engine, s_endpoints_rule_engine_destroy);

    return engine;
}

struct aws_endpoints_rule_engine *aws_endpoints_rule_engine_acquire(struct aws_endpoints_rule_engine *rule_engine) {
    AWS_PRECONDITION(rule_engine);
    if (rule_engine) {
        aws_ref_count_acquire(&rule_engine->ref_count);
    }
    return rule_engine;
}

struct aws_endpoints_rule_engine *aws_endpoints_rule_engine_release(struct aws_endpoints_rule_engine *rule_engine) {
    if (rule_engine) {
        aws_ref_count_release(&rule_engine->ref_count);
    }
    return NULL;
}

int s_revert_scope(struct aws_endpoints_resolution_state *state) {

    for (size_t idx = 0; idx < aws_array_list_length(&state->added_keys); ++idx) {
        struct aws_byte_cursor *cur = NULL;
        if (aws_array_list_get_at_ptr(&state->added_keys, (void **)&cur, idx)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to retrieve value.");
            return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
        }

        aws_hash_table_remove(&state->scope.values, cur, NULL, NULL);
    }

    aws_array_list_clear(&state->added_keys);

    return AWS_OP_SUCCESS;
}

int aws_endpoints_rule_engine_resolve(
    struct aws_endpoints_rule_engine *engine,
    const struct aws_endpoints_request_context *context,
    struct aws_endpoints_resolved_endpoint **out_resolved_endpoint) {

    if (aws_array_list_length(&engine->ruleset->rules) == 0) {
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EMPTY_RULESET);
    }

    int result = AWS_OP_SUCCESS;
    struct aws_endpoints_resolution_state state;
    if (s_init_top_level_scope(engine->allocator, context, engine->ruleset, engine->partitions_config, &state)) {
        result = AWS_OP_ERR;
        goto on_done;
    }

    while (state.rule_idx < aws_array_list_length(state.rules)) {
        struct aws_endpoints_rule *rule = NULL;
        if (aws_array_list_get_at_ptr(state.rules, (void **)&rule, state.rule_idx)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to get rule.");
            result = AWS_OP_ERR;
            goto on_done;
        }

        bool is_truthy = false;
        if (s_resolve_conditions(engine->allocator, &rule->conditions, &state, &is_truthy)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve conditions.");
            result = AWS_OP_ERR;
            goto on_done;
        }

        if (!is_truthy) {
            s_revert_scope(&state);
            ++state.rule_idx;
            continue;
        }

        switch (rule->type) {
            case AWS_ENDPOINTS_RULE_ENDPOINT: {
                struct aws_endpoints_resolved_endpoint *endpoint = aws_endpoints_resolved_endpoint_new(engine->allocator);
                endpoint->type = AWS_ENDPOINTS_RESOLVED_ENDPOINT;

                struct aws_endpoints_value val;
                if (aws_endpoints_resolve_expr(engine->allocator, rule->rule_data.endpoint.url_expr_ref, &state.scope, &val) ||
                    val.type != AWS_ENDPOINTS_VALUE_STRING ||
                    aws_byte_buf_init_copy_from_cursor(
                        &endpoint->r.endpoint.url, engine->allocator, val.v.owning_cursor_string.cur)) {
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve templated url.");
                    result = AWS_OP_ERR;
                    goto on_done;
                }

                aws_endpoints_value_clean_up(&val);

                struct resolve_template_callback_data data = {.allocator = engine->allocator, .scope = &state.scope};

                if (rule->rule_data.endpoint.properties.len > 0 &&
                    aws_byte_buf_init_from_resolved_templated_string(
                        engine->allocator,
                        &endpoint->r.endpoint.properties,
                        aws_byte_cursor_from_buf(&rule->rule_data.endpoint.properties),
                        aws_endpoints_resolve_template,
                        &data,
                        true)) {
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve templated properties.");
                    result = AWS_OP_ERR;
                    goto on_done;
                }

                if (aws_endpoints_resolve_headers(
                        engine->allocator, &state.scope, &rule->rule_data.endpoint.headers, &endpoint->r.endpoint.headers)) {
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve templated headers.");
                    result = AWS_OP_ERR;
                    goto on_done;
                }

                *out_resolved_endpoint = endpoint;
                goto on_done;
            }
            case AWS_ENDPOINTS_RULE_ERROR: {
                struct aws_endpoints_resolved_endpoint *error = aws_endpoints_resolved_endpoint_new(engine->allocator);
                error->type = AWS_ENDPOINTS_RESOLVED_ERROR;

                struct aws_endpoints_value val;
                if (aws_endpoints_resolve_expr(engine->allocator, rule->rule_data.error.error_expr_ref, &state.scope, &val) ||
                    val.type != AWS_ENDPOINTS_VALUE_STRING ||
                    aws_byte_buf_init_copy_from_cursor(
                        &error->r.error, engine->allocator, val.v.owning_cursor_string.cur)) {
                    aws_endpoints_value_clean_up(&val);
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve templated url.");
                    result = AWS_OP_ERR;
                    goto on_done;
                }

                aws_endpoints_value_clean_up(&val);
                *out_resolved_endpoint = error;
                goto on_done;
            }
            case AWS_ENDPOINTS_RULE_TREE: {
                /* jumping down a level */
                aws_array_list_clear(&state.added_keys);
                state.rule_idx = 0;
                state.rules = &rule->rule_data.tree.rules;
                continue;
            }
            default: {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Unexpected rule type.");
                result = aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
                goto on_done;
            }
        }
    }

    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "All rules have been exhausted.");
    result = aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RULESET_EXHAUSTED);

on_done:
    s_state_clean_up(&state);
    return result;
}
