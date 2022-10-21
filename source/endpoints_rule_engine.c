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

/* TODO: code uses terms resolve and eval interchangeably. Pick one. */

/*
 * How rule resolution works.
 * Note: read comments in endpoint_types_impl.h first to understand type system.
 *
 * Initial scope is created from parameters defined in request context and
 * default values defined in ruleset (s_init_top_level_scope). Validation that
 * all required parameters have values is done at this point as well.
 *
 * Rules are then evaluated sequentially against scope.
 * First list of conditions associated with the rule is evaluated
 * (s_eval_conditions). Final result of conditions evaluation is an AND of
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
 * values in scope top level whenever tree is jumped into. So in practice eval
 * goes back between top level and first level as evaluating rules. If that
 * changes in future, scope can add explicit level number and cleanup only values
 * at that level when going to next rule.
 *
 * Overall flow is as follows:
 * - Start with any values provided in context as scope
 * - Add any default values provided in ruleset and validate all required
 *   params are specified.
 * - Iterate through rules and resolve each rule:
 * -- eval conditions with side effects
 * -- if conditions are truthy return rule result
 * -- if conditions are truthy and rule is tree, jump down a level and
 *   restart eval with tree rules
 * -- if conditions are falsy, rollback level and go to next rule
 * - if no rules match, eval fails with exhausted error.
 */

struct resolve_template_callback_data {
    struct aws_allocator *allocator;
    struct eval_scope *scope;
};

static struct scope_value *s_scope_value_new(struct aws_allocator *allocator, struct aws_byte_cursor name_cur) {
    AWS_PRECONDITION(allocator);
    struct scope_value *value = aws_mem_calloc(allocator, 1, sizeof(struct scope_value));

    value->allocator = allocator;
    value->name = aws_string_new_from_cursor(allocator, &name_cur);
    value->name_cur = aws_byte_cursor_from_string(value->name);

    return value;
}

static void s_scope_value_destroy(struct scope_value *scope_value) {
    aws_string_destroy(scope_value->name);
    aws_endpoints_eval_value_clean_up(&scope_value->value);
    aws_mem_release(scope_value->allocator, scope_value);
}

static void s_callback_eval_value_destroy(void *data) {
    struct scope_value *value = data;
    s_scope_value_destroy(value);
}

static int s_deep_copy_value(struct aws_allocator *allocator, const struct scope_value *from, struct scope_value *to) {
    to->value.type = from->value.type;

    if (to->value.type == AWS_ENDPOINTS_EVAL_VALUE_STRING) {
        to->value.v.string =
            aws_endpoints_owning_cursor_create(aws_string_new_from_cursor(allocator, &from->value.v.string.cur));
    } else if (to->value.type == AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN) {
        to->value.v.boolean = from->value.v.boolean;
    } else {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unexpected value type.");
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    return AWS_OP_SUCCESS;
}

AWS_STATIC_ASSERT(AWS_ENDPOINTS_EVAL_VALUE_SIZE == 7);
static bool is_value_truthy(const struct eval_value *value) {
    switch (value->type) {
        case AWS_ENDPOINTS_EVAL_VALUE_NONE:
            return false;
        case AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN:
            return value->v.boolean;
        case AWS_ENDPOINTS_EVAL_VALUE_ARRAY:
        case AWS_ENDPOINTS_EVAL_VALUE_STRING:
        case AWS_ENDPOINTS_EVAL_VALUE_OBJECT:
            return true;
        case AWS_ENDPOINTS_EVAL_VALUE_NUMBER:
            return value->v.number != 0;
        default:
            AWS_ASSERT(false);
            return false;
    }
}

static int s_deep_copy_context_to_scope(
    struct aws_allocator *allocator,
    const struct aws_endpoints_request_context *context,
    struct eval_scope *scope) {

    struct scope_value *new_value = NULL;

    if (aws_hash_table_init(
            &scope->values,
            allocator,
            0,
            aws_hash_byte_cursor_ptr,
            aws_endpoints_byte_cursor_eq,
            NULL,
            s_callback_eval_value_destroy)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to init request context values.");
        goto on_error;
    }

    for (struct aws_hash_iter iter = aws_hash_iter_begin(&context->values); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {

        struct scope_value *context_value = (struct scope_value *)iter.element.value;

        new_value = s_scope_value_new(allocator, context_value->name_cur);
        if (s_deep_copy_value(allocator, context_value, new_value)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to deep copy value.");
            goto on_error;
        }

        if (aws_hash_table_put(&scope->values, &new_value->name_cur, new_value, NULL)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to add deep copy to scope.");
            goto on_error;
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    if (new_value != NULL) {
        s_scope_value_destroy(new_value);
    }
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_INIT_FAILED);
}

static int s_init_top_level_scope(
    struct aws_allocator *allocator,
    const struct aws_endpoints_request_context *context,
    const struct aws_endpoints_ruleset *ruleset,
    const struct aws_partitions_config *partitions,
    struct eval_scope *scope) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(context);
    AWS_PRECONDITION(ruleset);
    AWS_PRECONDITION(scope);

    struct scope_value *val = NULL;
    scope->rule_idx = 0;
    scope->rules = &ruleset->rules;
    scope->partitions = partitions;

    if (s_deep_copy_context_to_scope(allocator, context, scope)) {
        goto on_error;
    }

    if (aws_array_list_init_dynamic(&scope->added_keys, allocator, 10, sizeof(struct aws_byte_cursor))) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to init added keys.");
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
        if (aws_hash_table_find(&scope->values, &key, &existing)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to init request context values.");
            return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_INIT_FAILED);
        }

        if (existing == NULL) {
            if (!value->has_default_value) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "No value or default for required parameter.");
                goto on_error;
            }

            val = s_scope_value_new(allocator, key);
            AWS_ASSERT(val);

            switch (value->type) {
                case AWS_ENDPOINTS_PARAMETER_STRING:
                    val->value.type = AWS_ENDPOINTS_EVAL_VALUE_STRING;
                    val->value.v.string = aws_endpoints_non_owning_cursor_create(value->default_value.string);
                    break;
                case AWS_ENDPOINTS_PARAMETER_BOOLEAN:
                    val->value.type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
                    val->value.v.boolean = value->default_value.boolean;
                    break;
                default:
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unexpected parameter type.");
                    goto on_error;
            }

            if (aws_hash_table_put(&scope->values, &val->name_cur, val, NULL)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to add value to top level scope.");
                goto on_error;
            }
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    if (val != NULL) {
        s_scope_value_destroy(val);
    }
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_INIT_FAILED);
}

static void s_scope_clean_up(struct eval_scope *scope) {
    AWS_PRECONDITION(scope);

    aws_hash_table_clean_up(&scope->values);
    aws_array_list_clean_up(&scope->added_keys);
}

static int s_eval_expr(
    struct aws_allocator *allocator,
    struct aws_endpoints_expr *expr,
    struct eval_scope *scope,
    struct eval_value *out_value);

static struct aws_string *s_resolve_template(struct aws_byte_cursor template, void *user_data);

int aws_endpoints_argv_expect(
    struct aws_allocator *allocator,
    struct eval_scope *scope,
    struct aws_array_list *argv,
    size_t idx,
    enum eval_value_type expected_type,
    struct eval_value *out_value) {
    AWS_ZERO_STRUCT(*out_value);
    struct aws_endpoints_expr argv_expr;
    if (aws_array_list_get_at(argv, &argv_expr, idx)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to parse argv");
        goto on_error;
    }

    struct eval_value argv_value;
    if (s_eval_expr(allocator, &argv_expr, scope, &argv_value)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval argv.");
        goto on_error;
    }

    if (expected_type != AWS_ENDPOINTS_EVAL_VALUE_ANY && argv_value.type != expected_type) {
        AWS_LOGF_ERROR(
            AWS_LS_SDKUTILS_ENDPOINTS_EVAL,
            "Unexpected arg type actual: %u expected %u.",
            argv_value.type,
            expected_type);
        goto on_error;
    }

    *out_value = argv_value;
    return AWS_OP_SUCCESS;

on_error:
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

/*
******************************
* Expr/String eval
******************************
*/

static int s_eval_expr(
    struct aws_allocator *allocator,
    struct aws_endpoints_expr *expr,
    struct eval_scope *scope,
    struct eval_value *out_value) {
    AWS_ZERO_STRUCT(*out_value);
    switch (expr->type) {
        case AWS_ENDPOINTS_EXPR_STRING: {
            struct aws_byte_buf buf;
            struct resolve_template_callback_data data = {.allocator = allocator, .scope = scope};
            if (aws_byte_buf_init_from_resolved_templated_string(
                    allocator, &buf, expr->e.string, s_resolve_template, &data, false)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to resolve templated string.");
                goto on_error;
            }

            out_value->type = AWS_ENDPOINTS_EVAL_VALUE_STRING;
            out_value->v.string = aws_endpoints_owning_cursor_create(aws_string_new_from_buf(allocator, &buf));
            aws_byte_buf_clean_up(&buf);
            break;
        }
        case AWS_ENDPOINTS_EXPR_BOOLEAN: {
            out_value->type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
            out_value->v.boolean = expr->e.boolean;
            break;
        }
        case AWS_ENDPOINTS_EXPR_NUMBER: {
            out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NUMBER;
            out_value->v.number = expr->e.number;
            break;
        }
        case AWS_ENDPOINTS_EXPR_ARRAY: {
            out_value->type = AWS_ENDPOINTS_EVAL_VALUE_ARRAY;
            /* TODO: deep copy */
            out_value->v.array = expr->e.array;
            break;
        }
        case AWS_ENDPOINTS_EXPR_REFERENCE: {
            struct aws_hash_element *element;
            if (aws_hash_table_find(&scope->values, &expr->e.reference, &element)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to deref.");
                goto on_error;
            }

            if (element == NULL) {
                out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;
            } else {
                struct scope_value *scope_value = element->value;
                *out_value = scope_value->value;
                if (scope_value->value.type == AWS_ENDPOINTS_EVAL_VALUE_STRING) {
                    out_value->v.string.string = NULL;
                } else if (scope_value->value.type == AWS_ENDPOINTS_EVAL_VALUE_OBJECT) {
                    out_value->v.object.string = NULL;
                }
            }
            break;
        }
        case AWS_ENDPOINTS_EXPR_FUNCTION: {
            if (aws_endpoints_dispatch_standard_lib_fn_resolve(
                    expr->e.function.fn, allocator, &expr->e.function.argv, scope, out_value)) {
                goto on_error;
            }
            break;
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_eval_conditions(
    struct aws_allocator *allocator,
    const struct aws_array_list *conditions,
    struct eval_scope *scope,
    bool *out_is_truthy) {

    *out_is_truthy = false;
    for (size_t idx = 0; idx < aws_array_list_length(conditions); ++idx) {
        struct aws_endpoints_condition *condition = NULL;
        if (aws_array_list_get_at_ptr(conditions, (void **)&condition, idx)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to retrieve condition.");
            goto on_error;
        }

        struct eval_value val;
        if (s_eval_expr(allocator, &condition->expr, scope, &val)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to evaluate expr.");
            goto on_error;
        }

        /* truthiness of all conditions is and of each condition truthiness,
            hence first false one short circuits */
        if (!is_value_truthy(&val)) {
            goto on_short_circuit;
        }

        if (condition->assign.len > 0) {
            struct scope_value *scope_value = s_scope_value_new(allocator, condition->assign);
            scope_value->value = val;

            if (aws_array_list_push_back(&scope->added_keys, &scope_value->name_cur)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to update key at given scope.");
                goto on_error;
            }

            int was_created = 1;
            if (aws_hash_table_put(&scope->values, &scope_value->name_cur, scope_value, &was_created)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to set assigned variable.");
                goto on_error;
            }

            /* Shadowing existing values is prohibited in sep. */
            if (!was_created) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Assigned variable shadows existing one.");
                goto on_error;
            }
        }
    }

    *out_is_truthy = true;

on_short_circuit:
    return AWS_OP_SUCCESS;

on_error:
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

int aws_endpoints_path_through_array(
    struct aws_allocator *allocator,
    struct eval_scope *scope,
    struct eval_value *eval_val,
    struct aws_byte_cursor path_cur,
    struct eval_value *out_value) {

    AWS_PRECONDITION(eval_val->type == AWS_ENDPOINTS_EVAL_VALUE_ARRAY);

    uint64_t index;
    struct aws_byte_cursor split = {0};
    if ((!aws_byte_cursor_next_split(&path_cur, '[', &split) || split.len > 0) ||
        !aws_byte_cursor_next_split(&path_cur, ']', &split) || aws_byte_cursor_utf8_parse_u64(split, &index)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Could not parse index from template string.");
        goto on_error;
    }

    if (index < aws_array_list_length(&eval_val->v.array)) {
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;
        return AWS_OP_SUCCESS;
    }

    struct aws_endpoints_expr *expr = NULL;
    if (aws_array_list_get_at_ptr(&eval_val->v.array, (void **)&expr, (size_t)index)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to index into evaluated value");
        goto on_error;
    }

    struct eval_value val;
    if (s_eval_expr(allocator, expr, scope, &val)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to evaluate val.");
        aws_endpoints_eval_value_clean_up(&val);
        goto on_error;
    }

    *out_value = val;
    return AWS_OP_SUCCESS;

on_error:
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

int aws_endpoints_path_through_object(
    struct aws_allocator *allocator,
    struct eval_value *eval_val,
    struct aws_byte_cursor path_cur,
    struct eval_value *out_value) {

    AWS_ZERO_STRUCT(*out_value);
    struct aws_json_value *root_node = NULL;

    /* TODO: needed? */
    struct aws_byte_cursor val_cur =
        eval_val->type != AWS_ENDPOINTS_EVAL_VALUE_STRING ? eval_val->v.string.cur : eval_val->v.object.cur;

    root_node = aws_json_value_new_from_string(allocator, val_cur);
    const struct aws_json_value *result;
    if (aws_path_through_json(allocator, root_node, path_cur, &result)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to path through json.");
        goto on_error;
    }

    if (result == NULL) {
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;
    } else if (aws_json_value_is_string(result)) {
        struct aws_byte_cursor final;
        if (aws_json_value_get_string(result, &final)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Could not parse string from node.");
            goto on_error;
        }
        struct eval_value eval = {
            .type = AWS_ENDPOINTS_EVAL_VALUE_STRING,
            .v.string = aws_endpoints_owning_cursor_create(aws_string_new_from_cursor(allocator, &final)),
        };

        *out_value = eval;
    } else if (aws_json_value_is_array(result) || aws_json_value_is_object(result)) {
        struct aws_byte_buf json_blob;
        aws_byte_buf_init(&json_blob, allocator, 0);

        if (aws_byte_buf_append_json_string(result, &json_blob)) {
            aws_byte_buf_clean_up(&json_blob);
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to extract properties.");
            goto on_error;
        }

        struct eval_value eval = {
            .type = AWS_ENDPOINTS_EVAL_VALUE_OBJECT,
            .v.object = aws_endpoints_owning_cursor_create(aws_string_new_from_buf(allocator, &json_blob)),
        };

        aws_byte_buf_clean_up(&json_blob);
        *out_value = eval;
    } else if (aws_json_value_is_boolean(result)) {
        struct eval_value eval = {
            .type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN,
            .v.boolean = false,
        };

        if (aws_json_value_get_boolean(result, &eval.v.boolean)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Could not parse boolean from node.");
            goto on_error;
        }

        *out_value = eval;
    } else if (aws_json_value_is_number(result)) {
        struct eval_value eval = {
            .type = AWS_ENDPOINTS_EVAL_VALUE_NUMBER,
            .v.number = 0,
        };

        if (aws_json_value_get_number(result, &eval.v.number)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Could not parse number from node.");
            goto on_error;
        }

        *out_value = eval;
    }

    aws_json_value_destroy(root_node);
    return AWS_OP_SUCCESS;

on_error:
    aws_json_value_destroy(root_node);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_resolve_templated_value_with_pathing(
    struct aws_allocator *allocator,
    struct eval_scope *scope,
    struct aws_byte_cursor template_cur,
    struct aws_string **out_value) {

    struct aws_byte_cursor split = {0};
    if (!aws_byte_cursor_next_split(&template_cur, '#', &split) || split.len == 0) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Invalid value in template string.");
        goto on_error;
    }

    struct aws_hash_element *elem = NULL;
    if (aws_hash_table_find(&scope->values, &split, &elem) || elem == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Templated value does not exist: " PRInSTR, AWS_BYTE_CURSOR_PRI(split));
        goto on_error;
    }

    struct scope_value *eval_val = elem->value;
    struct eval_value resolved_value;

    if (!aws_byte_cursor_next_split(&template_cur, '#', &split)) {
        if (eval_val->value.type != AWS_ENDPOINTS_EVAL_VALUE_STRING) {
            AWS_LOGF_ERROR(
                AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unexpected eval type: must be string if pathing is not provided");
            goto on_error;
        }

        *out_value = aws_string_new_from_cursor(allocator, &eval_val->value.v.string.cur);
        return AWS_OP_SUCCESS;
    }

    if (eval_val->value.type == AWS_ENDPOINTS_EVAL_VALUE_OBJECT) {
        if (aws_endpoints_path_through_object(allocator, &eval_val->value, split, &resolved_value)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to path through object.");
            goto on_error;
        }
    } else if (eval_val->value.type == AWS_ENDPOINTS_EVAL_VALUE_ARRAY) {
        if (aws_endpoints_path_through_array(allocator, scope, &eval_val->value, split, &resolved_value)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to path through array.");
            goto on_error;
        }
    } else {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Invalid value type for pathing through.");
        goto on_error;
    }

    if (resolved_value.type != AWS_ENDPOINTS_EVAL_VALUE_STRING) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Templated string didn't eval to string");
        goto on_error;
    }

    *out_value = aws_string_new_from_cursor(allocator, &resolved_value.v.string.cur);
    aws_endpoints_eval_value_clean_up(&resolved_value);

    return AWS_OP_SUCCESS;

on_error:
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static struct aws_string *s_resolve_template(struct aws_byte_cursor template, void *user_data) {

    struct resolve_template_callback_data *data = user_data;

    struct aws_string *result;
    if (s_resolve_templated_value_with_pathing(data->allocator, data->scope, template, &result)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to resolve template value.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
        return NULL;
    }

    return result;
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
            s_callback_eval_value_destroy)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to init request context values.");
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

    struct scope_value *val = s_scope_value_new(allocator, name);
    val->value.type = AWS_ENDPOINTS_EVAL_VALUE_STRING;
    val->value.v.string = aws_endpoints_owning_cursor_create(aws_string_new_from_cursor(allocator, &value));

    if (aws_hash_table_put(&context->values, &val->name_cur, val, NULL)) {
        s_scope_value_destroy(val);
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_INIT_FAILED);
    };

    return AWS_OP_SUCCESS;
}

int aws_endpoints_request_context_add_boolean(
    struct aws_allocator *allocator,
    struct aws_endpoints_request_context *context,
    struct aws_byte_cursor name,
    bool value) {
    AWS_PRECONDITION(allocator);

    struct scope_value *val = s_scope_value_new(allocator, name);
    val->value.type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
    val->value.v.boolean = value;

    if (aws_hash_table_put(&context->values, &val->name_cur, val, NULL)) {
        s_scope_value_destroy(val);
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_INIT_FAILED);
    };

    return AWS_OP_SUCCESS;
}

/*
******************************
* Rule engine.
******************************
*/

struct aws_endpoints_resolved_endpoint {
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;
    enum aws_endpoints_resolved_endpoint_type type;
    union {
        struct resolved_endpoint {
            struct aws_byte_buf url;
            struct aws_byte_buf properties;
            struct aws_hash_table headers;
        } endpoint;
        struct aws_byte_buf error;
    } r;
};

static void s_endpoints_resolved_endpoint_destroy(void *data) {
    if (data == NULL) {
        return;
    }

    struct aws_endpoints_resolved_endpoint *resolved = data;
    if (resolved->type == AWS_ENDPOINTS_RESOLVED_ENDPOINT) {
        aws_byte_buf_clean_up(&resolved->r.endpoint.url);
        aws_byte_buf_clean_up(&resolved->r.endpoint.properties);
        aws_hash_table_clean_up(&resolved->r.endpoint.headers);
    } else if (resolved->type == AWS_ENDPOINTS_RESOLVED_ERROR) {
        aws_byte_buf_clean_up(&resolved->r.error);
    }
    aws_mem_release(resolved->allocator, resolved);
}

struct aws_endpoints_resolved_endpoint *s_endpoints_resolved_endpoint_new(struct aws_allocator *allocator) {
    AWS_PRECONDITION(allocator);

    struct aws_endpoints_resolved_endpoint *resolved =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_resolved_endpoint));
    resolved->allocator = allocator;

    aws_ref_count_init(&resolved->ref_count, resolved, s_endpoints_resolved_endpoint_destroy);

    return resolved;
}

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

int s_revert_scope(struct eval_scope *scope) {

    for (size_t idx = 0; idx < aws_array_list_length(&scope->added_keys); ++idx) {
        struct aws_byte_cursor *cur = NULL;
        if (aws_array_list_get_at_ptr(&scope->added_keys, (void **)&cur, idx)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to retrieve value.");
            return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
        }

        aws_hash_table_remove(&scope->values, cur, NULL, NULL);
    }

    aws_array_list_clear(&scope->added_keys);

    return AWS_OP_SUCCESS;
}

static void s_on_string_array_element_destroy(void *element) {
    struct aws_string *str = *(struct aws_string **)element;
    aws_string_destroy(str);
}

static void s_callback_headers_destroy(void *data) {
    struct aws_array_list *array = data;
    struct aws_allocator *alloc = array->alloc;
    aws_array_list_deep_clean_up(array, s_on_string_array_element_destroy);
    aws_mem_release(alloc, array);
}

static int s_resolve_headers(
    struct aws_allocator *allocator,
    struct eval_scope *scope,
    struct aws_hash_table *headers,
    struct aws_hash_table *out_headers) {
    struct eval_value eval;
    struct aws_array_list *resolved_headers = NULL;

    if (aws_hash_table_init(
            out_headers,
            allocator,
            aws_hash_table_get_entry_count(headers),
            aws_hash_string,
            aws_hash_callback_string_eq,
            aws_hash_callback_string_destroy,
            s_callback_headers_destroy)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to init table for resolved headers");
        goto on_error;
    }

    for (struct aws_hash_iter iter = aws_hash_iter_begin(headers); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {

        struct aws_string *key = (struct aws_string *)iter.element.key;
        struct aws_array_list *header_list = (struct aws_array_list *)iter.element.value;

        resolved_headers = aws_mem_calloc(allocator, 1, sizeof(struct aws_array_list));
        aws_array_list_init_dynamic(
            resolved_headers, allocator, aws_array_list_length(header_list), sizeof(struct aws_string *));

        for (size_t i = 0; i < aws_array_list_length(header_list); ++i) {
            struct aws_endpoints_expr *expr = NULL;
            if (aws_array_list_get_at_ptr(header_list, (void **)&expr, i)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to get header.");
                goto on_error;
            }

            if (s_eval_expr(allocator, expr, scope, &eval) || eval.type != AWS_ENDPOINTS_EVAL_VALUE_STRING) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval header expr.");
                goto on_error;
            }

            struct aws_string *str = aws_string_new_from_cursor(allocator, &eval.v.string.cur);
            if (aws_array_list_push_back(resolved_headers, &str)) {
                aws_string_destroy(str);
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed add resolved header to result.");
                goto on_error;
            }

            aws_endpoints_eval_value_clean_up(&eval);
        }

        if (aws_hash_table_put(out_headers, aws_string_clone_or_reuse(allocator, key), resolved_headers, NULL)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed add resolved header to result.");
            goto on_error;
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_eval_value_clean_up(&eval);
    if (resolved_headers != NULL) {
        s_callback_headers_destroy(resolved_headers);
    }
    aws_hash_table_clean_up(out_headers);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

int aws_endpoints_rule_engine_resolve(
    struct aws_endpoints_rule_engine *engine,
    const struct aws_endpoints_request_context *context,
    struct aws_endpoints_resolved_endpoint **out_resolved_endpoint) {

    if (aws_array_list_length(&engine->ruleset->rules) == 0) {
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EMPTY_RULESET);
    }

    struct eval_scope scope;
    if (s_init_top_level_scope(engine->allocator, context, engine->ruleset, engine->partitions_config, &scope)) {
        goto on_error;
    }

    while (scope.rule_idx < aws_array_list_length(scope.rules)) {
        struct aws_endpoints_rule *rule = NULL;
        if (aws_array_list_get_at_ptr(scope.rules, (void **)&rule, scope.rule_idx)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to get rule.");
            goto on_error;
        }

        bool is_truthy = false;
        if (s_eval_conditions(engine->allocator, &rule->conditions, &scope, &is_truthy)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to evaluate conditions.");
            goto on_error;
        }

        if (!is_truthy) {
            s_revert_scope(&scope);
            ++scope.rule_idx;
            continue;
        }

        switch (rule->type) {
            case AWS_ENDPOINTS_RULE_ENDPOINT: {
                struct aws_endpoints_resolved_endpoint *endpoint = s_endpoints_resolved_endpoint_new(engine->allocator);
                endpoint->type = AWS_ENDPOINTS_RESOLVED_ENDPOINT;

                struct eval_value val;
                if (s_eval_expr(engine->allocator, &rule->rule_data.endpoint.url, &scope, &val) ||
                    val.type != AWS_ENDPOINTS_EVAL_VALUE_STRING ||
                    aws_byte_buf_init_copy_from_cursor(
                        &endpoint->r.endpoint.url, engine->allocator, val.v.string.cur)) {
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to resolve templated url.");
                    goto on_error;
                }

                aws_endpoints_eval_value_clean_up(&val);

                struct resolve_template_callback_data data = {.allocator = engine->allocator, .scope = &scope};

                if (rule->rule_data.endpoint.properties.len > 0 &&
                    aws_byte_buf_init_from_resolved_templated_string(
                        engine->allocator,
                        &endpoint->r.endpoint.properties,
                        aws_byte_cursor_from_buf(&rule->rule_data.endpoint.properties),
                        s_resolve_template,
                        &data,
                        true)) {
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to resolve templated properties.");
                    goto on_error;
                }

                if (s_resolve_headers(
                        engine->allocator, &scope, &rule->rule_data.endpoint.headers, &endpoint->r.endpoint.headers)) {
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to resolve templated headers.");
                    goto on_error;
                }

                *out_resolved_endpoint = endpoint;
                goto on_success;
            }
            case AWS_ENDPOINTS_RULE_ERROR: {
                struct aws_endpoints_resolved_endpoint *error = s_endpoints_resolved_endpoint_new(engine->allocator);
                error->type = AWS_ENDPOINTS_RESOLVED_ERROR;

                struct eval_value val;
                if (s_eval_expr(engine->allocator, &rule->rule_data.error.error, &scope, &val) ||
                    val.type != AWS_ENDPOINTS_EVAL_VALUE_STRING ||
                    aws_byte_buf_init_copy_from_cursor(&error->r.error, engine->allocator, val.v.string.cur)) {
                    aws_endpoints_eval_value_clean_up(&val);
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to resolve templated url.");
                    goto on_error;
                }

                aws_endpoints_eval_value_clean_up(&val);
                *out_resolved_endpoint = error;
                goto on_success;
            }
            case AWS_ENDPOINTS_RULE_TREE: {
                /* jumping down a level */
                aws_array_list_clear(&scope.added_keys);
                scope.rule_idx = 0;
                scope.rules = &rule->rule_data.tree.rules;
                continue;
            }
            default: {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unexpected rule type.");
                aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
                goto on_error;
            }
        }
    }

    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "All rules have been exhausted.");
    aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RULESET_EXHAUSTED);
    goto on_error;

on_success:
    AWS_LOGF_DEBUG(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Successfully resolved endpoint.");
    s_scope_clean_up(&scope);
    return AWS_OP_SUCCESS;

on_error:
    AWS_LOGF_DEBUG(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unsuccessfully resolved endpoint.");
    s_scope_clean_up(&scope);
    return AWS_OP_ERR;
}
