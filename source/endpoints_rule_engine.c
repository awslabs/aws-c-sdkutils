/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>
#include <aws/common/json.h>
#include <aws/common/string.h>
#include <aws/sdkutils/private/endpoints_ruleset_types_impl.h>

/* TODO: checking for unknown enum values is annoying and is brittle. compile
time assert on enum size or members would make it a lot simpler. */

/* TODO: support array */
enum eval_value_type {
    AWS_ENDPOINTS_EVAL_VALUE_NONE,
    AWS_ENDPOINTS_EVAL_VALUE_STRING,
    AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN,
    AWS_ENDPOINTS_EVAL_VALUE_OBJECT,
    AWS_ENDPOINTS_EVAL_VALUE_NUMBER,
    AWS_ENDPOINTS_EVAL_VALUE_ARRAY
};

struct aws_endpoints_request_context {
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;

    struct aws_hash_table values;
};

/*
******************************
* Eval logic.
******************************
*/

struct eval_value {
    enum eval_value_type type;
    union {
        struct aws_string *string;
        bool boolean;
        struct aws_string *object;
        double number;
        struct aws_array_list array;
    } v;
    bool should_clean_up;
};

struct scope_value {
    struct aws_allocator *allocator;

    struct aws_byte_cursor name_cur;
    struct aws_string *name;

    struct eval_value value;
};

struct eval_scope {
    struct aws_hash_table values;
    struct aws_array_list added_keys;

    size_t rule_idx;
    const struct aws_array_list *rules;
};

static struct scope_value *s_scope_value_new(struct aws_allocator *allocator, struct aws_byte_cursor name_cur) {
    AWS_PRECONDITION(allocator);
    struct scope_value *value = aws_mem_calloc(allocator, 1, sizeof(struct scope_value));

    value->allocator = allocator;
    value->name = aws_string_new_from_cursor(allocator, &name_cur);
    value->name_cur = aws_byte_cursor_from_string(value->name);

    return value;
}

static void s_eval_value_clean_up_cb(void *value);

static void s_eval_value_clean_up(struct eval_value *eval_value, bool force_clean_up) {
    if (!(eval_value->should_clean_up || force_clean_up)) {
        return;
    }

    if (eval_value->type == AWS_ENDPOINTS_EVAL_VALUE_STRING) {
        aws_string_destroy(eval_value->v.string);
    }

    if (eval_value->type == AWS_ENDPOINTS_EVAL_VALUE_OBJECT) {
        aws_string_destroy(eval_value->v.object);
    }

    if (eval_value->type == AWS_ENDPOINTS_EVAL_VALUE_OBJECT) {
        aws_array_list_deep_clean_up(&eval_value->v.array, s_eval_value_clean_up_cb);
    }
}

static void s_eval_value_clean_up_cb(void *value) {
    struct eval_value *eval_value = value;
    s_eval_value_clean_up(eval_value, true);
}

static void s_scope_value_destroy(struct scope_value *scope_value) {
    aws_string_destroy(scope_value->name);
    s_eval_value_clean_up(&scope_value->value, true);
    aws_mem_release(scope_value->allocator, scope_value);
}

static void s_callback_eval_value_destroy(void *data) {
    struct scope_value *value = data;
    s_scope_value_destroy(value);
}

static int s_deep_copy_value(struct aws_allocator *allocator, const struct scope_value *from, struct scope_value *to) {
    to->value.type = from->value.type;

    if (to->value.type == AWS_ENDPOINTS_EVAL_VALUE_STRING) {
        to->value.v.string = aws_string_clone_or_reuse(allocator, from->value.v.string);
    } else if (to->value.type == AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN) {
        to->value.v.boolean = from->value.v.boolean;
    } else {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unexpected value type.");
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    return AWS_OP_SUCCESS;
}

static int is_value_truthy(const struct eval_value *value, bool *is_truthy) {
    switch (value->type) {
        case AWS_ENDPOINTS_EVAL_VALUE_NONE:
            *is_truthy = false;
            return AWS_OP_SUCCESS;
        case AWS_ENDPOINTS_EVAL_VALUE_STRING:
            *is_truthy = value->v.string->len > 0;
            return AWS_OP_SUCCESS;
        case AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN:
            *is_truthy = value->v.boolean;
            return AWS_OP_SUCCESS;
        case AWS_ENDPOINTS_EVAL_VALUE_OBJECT:
            *is_truthy = true;
            return AWS_OP_SUCCESS;
        case AWS_ENDPOINTS_EVAL_VALUE_NUMBER:
            *is_truthy = value->v.number != 0;
            return AWS_OP_SUCCESS;
        default:
            *is_truthy = false;
            return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
    }

    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
    ;
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

        aws_hash_table_put(&scope->values, &new_value->name_cur, new_value, NULL);
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
    struct eval_scope *scope) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(context);
    AWS_PRECONDITION(ruleset);
    AWS_PRECONDITION(scope);

    struct scope_value *val = NULL;
    scope->rule_idx = 0;
    scope->rules = &ruleset->rules;

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

            if (value->type == AWS_ENDPOINTS_PARAMETER_STRING) {
                val->value.type = AWS_ENDPOINTS_EVAL_VALUE_STRING;
                val->value.v.string = aws_string_clone_or_reuse(allocator, value->default_value.string);
            } else if (value->type == AWS_ENDPOINTS_PARAMETER_STRING) {
                val->value.type = AWS_ENDPOINTS_EVAL_VALUE_STRING;
                val->value.v.boolean = value->default_value.boolean;
            } else {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unexpected parameter type.");
                goto on_error;
            }

            if (aws_hash_table_put(&scope->values, &key, val, NULL)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unexpected parameter type.");
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

static void s_scope_clean_up(struct aws_allocator *allocator, struct eval_scope *scope) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(scope);

    aws_hash_table_clean_up(&scope->values);
    aws_array_list_clean_up(&scope->added_keys);
}

static int s_eval_expr(
    struct aws_allocator *allocator,
    struct aws_endpoints_expr *expr,
    struct eval_scope *scope,
    struct eval_value *out_value) {
    switch (expr->type) {
        case AWS_ENDPOINTS_EXPR_STRING: {
            out_value->type = AWS_ENDPOINTS_EVAL_VALUE_STRING;
            out_value->v.string = aws_string_clone_or_reuse(allocator, expr->e.string);
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
            struct aws_byte_cursor ref_key = aws_byte_cursor_from_string(expr->e.reference);
            if (aws_hash_table_find(&scope->values, &ref_key, &element)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to deref.");
                goto on_error;
            }

            if (element == NULL) {
                out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;
            } else {
                struct scope_value *scope_value = element->value;
                *out_value = scope_value->value;
            }
        }
        case AWS_ENDPOINTS_EXPR_FUNCTION: {
            switch (expr->e.function.fn) {
                case AWS_ENDPOINTS_FN_IS_SET: {
                    struct aws_endpoints_expr argv_expr;
                    if (aws_array_list_get_at(&expr->e.function.argv, &argv_expr, 0)) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to extract args for isSet.");
                        goto on_error;
                    }

                    struct eval_value argv_value;
                    if (s_eval_expr(allocator, &argv_expr, scope, &argv_value)) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval isSet.");
                        goto on_error;
                    }

                    out_value->should_clean_up = true;
                    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
                    out_value->v.boolean = argv_value.type == AWS_ENDPOINTS_EVAL_VALUE_NONE;
                    s_eval_value_clean_up(&argv_value, false);

                    break;
                }
                case AWS_ENDPOINTS_FN_NOT: {
                    struct aws_endpoints_expr argv_expr;
                    if (aws_array_list_get_at(&expr->e.function.argv, &argv_expr, 0)) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to args for not.");
                        goto on_error;
                    }

                    struct eval_value argv_value;
                    if (s_eval_expr(allocator, &argv_expr, scope, &argv_value)) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval not.");
                        goto on_error;
                    }

                    if (argv_value.type != AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unexpected arg type for not.");
                        goto on_error;
                    }

                    out_value->should_clean_up = true;
                    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
                    out_value->v.boolean = !argv_value.v.boolean;
                    s_eval_value_clean_up(&argv_value, false);

                    break;
                }
                case AWS_ENDPOINTS_FN_STRING_EQUALS: {
                    struct aws_endpoints_expr argv_expr_1;
                    struct aws_endpoints_expr argv_expr_2;
                    if (aws_array_list_get_at(&expr->e.function.argv, &argv_expr_1, 0) ||
                        aws_array_list_get_at(&expr->e.function.argv, &argv_expr_2, 1)) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to args for stringEquals.");
                        goto on_error;
                    }

                    struct eval_value argv_value_1;
                    struct eval_value argv_value_2;
                    if (s_eval_expr(allocator, &argv_expr_1, scope, &argv_value_1) ||
                        s_eval_expr(allocator, &argv_expr_2, scope, &argv_value_2)) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval stringEquals.");
                        goto on_error;
                    }

                    if (argv_value_1.type != AWS_ENDPOINTS_EVAL_VALUE_STRING ||
                        argv_value_2.type != AWS_ENDPOINTS_EVAL_VALUE_STRING) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unexpected arg type for stringEquals.");
                        goto on_error;
                    }

                    out_value->should_clean_up = true;
                    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
                    out_value->v.boolean = aws_string_compare(argv_value_1.v.string, argv_value_2.v.string) == 0;
                    s_eval_value_clean_up(&argv_value_1, false);
                    s_eval_value_clean_up(&argv_value_2, false);

                    break;
                }
                case AWS_ENDPOINTS_FN_BOOLEAN_EQUALS: {
                    struct aws_endpoints_expr argv_expr_1;
                    struct aws_endpoints_expr argv_expr_2;
                    if (aws_array_list_get_at(&expr->e.function.argv, &argv_expr_1, 0) ||
                        aws_array_list_get_at(&expr->e.function.argv, &argv_expr_2, 1)) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to args for booleanEquals.");
                        goto on_error;
                    }

                    struct eval_value argv_value_1;
                    struct eval_value argv_value_2;
                    if (s_eval_expr(allocator, &argv_expr_1, scope, &argv_value_1) ||
                        s_eval_expr(allocator, &argv_expr_2, scope, &argv_value_2)) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval booleanEquals.");
                        goto on_error;
                    }

                    if (argv_value_1.type != AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN ||
                        argv_value_2.type != AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unexpected arg type for booleanEquals.");
                        goto on_error;
                    }

                    out_value->should_clean_up = true;
                    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
                    out_value->v.boolean = argv_value_1.v.boolean == argv_value_2.v.boolean;
                    s_eval_value_clean_up(&argv_value_1, false);
                    s_eval_value_clean_up(&argv_value_2, false);

                    break;
                }

                case AWS_ENDPOINTS_FN_AWS_PARTITION: {
                    out_value->should_clean_up = true;
                    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_OBJECT;
                    out_value->v.object = aws_string_new_from_c_str(
                        allocator,
                        "{\"name\": \"aws\",\"dnsSuffix\": \"amazonaws.com\",\"dualStackDnsSuffix\": \"api.aws\","
                        "\"supportsFIPS\": true, \"supportsDualStack\": true}");

                    break;
                }

                case AWS_ENDPOINTS_FN_GET_ATTR:
                case AWS_ENDPOINTS_FN_SUBSTRING:
                case AWS_ENDPOINTS_FN_URI_ENCODE:
                case AWS_ENDPOINTS_FN_PARSE_URL:
                case AWS_ENDPOINTS_FN_IS_VALID_HOST_LABEL:
                case AWS_ENDPOINTS_FN_AWS_PARSE_ARN:
                case AWS_ENDPOINTS_FN_AWS_IS_VIRTUAL_HOSTABLE_S3_BUCKET:
                case AWS_ENDPOINTS_FN_LAST:
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "fn type not supported yet.");
                    goto on_error;
                    break;
            }
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

        /* TODO: can safe construction here by parsing it as expr to begin with */
        struct aws_endpoints_expr expr = {
            .type = AWS_ENDPOINTS_EXPR_FUNCTION,
            .e.function = condition->function,
        };

        struct eval_value val;
        if (s_eval_expr(allocator, &expr, scope, &val)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to evaluate expr.");
            goto on_error;
        }

        bool truthy = false;
        if (is_value_truthy(&val, &truthy)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unexpected resolved value.");
            goto on_error;
        }

        if (!truthy) {
            goto on_short_circuit;
        }

        if (condition->assign != NULL) {
            struct scope_value *scope_value =
                s_scope_value_new(allocator, aws_byte_cursor_from_string(condition->assign));
            scope_value->value = val;

            if (aws_array_list_push_back(&scope->added_keys, &scope_value->name_cur)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to update key at given scope.");
                goto on_error;
            }

            if (aws_hash_table_put(&scope->values, &scope_value->name_cur, &scope_value, NULL)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to update key at given scope.");
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

static struct aws_byte_cursor s_byte_cursor_from_substring(const struct aws_string *src, size_t start, size_t end) {
    AWS_PRECONDITION(aws_string_is_valid(src));
    AWS_PRECONDITION(start < end && end < src->len);

    return aws_byte_cursor_from_array(aws_string_bytes(src) + start, end - start);
}

static bool is_closing_bracket(uint8_t c) {
    return c == ']';
}

static int s_resolve_templated_value_with_pathing(
    struct aws_allocator *allocator,
    struct eval_scope *scope,
    struct aws_byte_cursor template_cur,
    struct aws_string **out_value) {

    struct aws_json_value *root_node = NULL;

    struct aws_byte_cursor path_delim = aws_byte_cursor_from_c_str("#");
    struct aws_byte_cursor path_cur;
    int error = aws_byte_cursor_find_exact(&template_cur, &path_delim, &path_cur);

    bool has_path = error == AWS_OP_SUCCESS;
    if (error && aws_last_error() != AWS_ERROR_STRING_MATCH_NOT_FOUND) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Could not parse path in template string.");
        goto on_error;
    }

    if (has_path) {
        AWS_ASSERT(path_cur.ptr > template_cur.ptr);
        template_cur.len = path_cur.ptr - template_cur.ptr;
        aws_byte_cursor_advance(&path_cur, 1);
    }

    if (template_cur.len < 1 || path_cur.len < 1) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Invalid value or path in template string.");
        goto on_error;
    }

    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Template string: " PRInSTR, AWS_BYTE_CURSOR_PRI(template_cur));

    struct aws_hash_element *elem = NULL;
    if (aws_hash_table_find(&scope->values, &template_cur, &elem) || elem == NULL) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Invalid value in templated string.");
        goto on_error;
    }

    struct scope_value *eval_val = elem->value;
    if (eval_val->value.type != AWS_ENDPOINTS_EVAL_VALUE_STRING) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Invalid value type.");
        goto on_error;
    }

    struct aws_array_list path_segments;
    if (aws_array_list_init_dynamic(&path_segments, allocator, 10, sizeof(struct aws_byte_cursor))) {
        goto on_error;
    }

    if (aws_byte_cursor_split_on_char(&path_cur, '.', &path_segments)) {
        goto on_error;
    }

    struct aws_byte_cursor val_cur = aws_byte_cursor_from_string(eval_val->value.v.string);
    root_node = aws_json_value_new_from_string(allocator, val_cur);
    struct aws_json_value *node = root_node;
    struct aws_byte_cursor path_el_cur;

    for (size_t idx = 0; idx < aws_array_list_length(&path_segments); ++idx) {

        aws_array_list_get_at(&path_segments, &path_el_cur, idx);

        struct aws_byte_cursor index_opening_char = aws_byte_cursor_from_c_str("[");
        struct aws_byte_cursor index_cur;
        int error = aws_byte_cursor_find_exact(&path_el_cur, &index_opening_char, &index_cur);
        bool has_index = error == AWS_OP_SUCCESS;
        if (error && error != AWS_ERROR_STRING_MATCH_NOT_FOUND) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Could not parse path in template string.");
            goto on_error;
        }

        if (has_index) {
            path_el_cur.len = index_cur.ptr - path_el_cur.ptr;
            aws_byte_cursor_advance(&index_cur, 1);
            aws_byte_cursor_right_trim_pred(&index_cur, is_closing_bracket);
        }

        node = aws_json_value_get_from_object(node, path_el_cur);

        if (node == NULL) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Invalid path.");
            goto on_error;
        }

        if (has_index) {
            uint64_t index;
            if (aws_byte_cursor_utf8_parse_u64(index_cur, &index)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to parse index.");
                goto on_error;
            }

            node = aws_json_get_array_element(node, index);

            if (node == NULL) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to index into value.");
                goto on_error;
            }
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    if (root_node) {
        aws_json_value_destroy(root_node);
    }

    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

int s_resolve_templated_string(
    struct aws_allocator *allocator,
    struct aws_string *string,
    struct eval_scope *scope,
    struct aws_byte_buf *out_result_buf) {

    if (aws_byte_buf_init(out_result_buf, allocator, string->len)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to init resolved buffer.");
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
    }

    size_t copy_start = 0;
    size_t opening_idx = SIZE_MAX;
    for (size_t idx = 0; idx < string->len; ++idx) {
        if (string->bytes[idx] == '{') {
            if ((idx + 1) >= string->len) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Invalid template string syntax.");
                goto on_error;
            }

            if (string->bytes[idx + 1] == '{') {
                struct aws_byte_cursor cur = s_byte_cursor_from_substring(string, copy_start, idx + 1);

                aws_byte_buf_append_dynamic(out_result_buf, &cur);
                ++idx;
                copy_start = idx + 1;
            } else {
                opening_idx = idx;
            }
            continue;
        }

        if (string->bytes[idx] == '}') {
            if ((idx + 1) >= string->len && string->bytes[idx + 1] != '}') {
                if (opening_idx != SIZE_MAX) {
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Invalid template string syntax.");
                    goto on_error;
                }
                struct aws_byte_cursor cur = s_byte_cursor_from_substring(string, copy_start, idx);

                aws_byte_buf_append_dynamic(out_result_buf, &cur);
                ++idx;
                copy_start = idx;
                continue;
            }

            if (opening_idx == SIZE_MAX) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Invalid template string syntax.");
                goto on_error;
            }

            struct aws_byte_cursor cur = s_byte_cursor_from_substring(string, copy_start, opening_idx + 1);

            aws_byte_buf_append_dynamic(out_result_buf, &cur);

            struct aws_byte_cursor template_cur = s_byte_cursor_from_substring(string, opening_idx + 1, idx);

            struct aws_string *resolved_template = NULL;
            if (s_resolve_templated_value_with_pathing(allocator, scope, template_cur, &resolved_template)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Invalid template string syntax.");
                goto on_error;
            }

            struct aws_byte_cursor resolved_template_cur = aws_byte_cursor_from_string(resolved_template);
            aws_byte_buf_append_dynamic(out_result_buf, &resolved_template_cur);
            copy_start = idx + 1;
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    aws_byte_buf_clean_up(out_result_buf);

    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
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
    val->value.v.string = aws_string_new_from_cursor(allocator, &value);
    val->value.should_clean_up = false;

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
    val->value.should_clean_up = false;

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
};

static void s_endpoints_rule_engine_destroy(void *data) {
    if (data == NULL) {
        return;
    }

    struct aws_endpoints_rule_engine *engine = data;
    aws_endpoints_ruleset_release(engine->ruleset);

    aws_mem_release(engine->allocator, engine);
}

struct aws_endpoints_rule_engine *aws_endpoints_rule_engine_new(
    struct aws_allocator *allocator,
    struct aws_endpoints_ruleset *ruleset) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(ruleset);

    struct aws_endpoints_rule_engine *engine = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_rule_engine));
    engine->allocator = allocator;
    engine->ruleset = ruleset;

    aws_endpoints_ruleset_acquire(ruleset);
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
        if (aws_array_list_get_at(&scope->added_keys, (void **)&cur, idx)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to retrieve value.");
            return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
        }

        aws_hash_table_remove(&scope->values, cur, NULL, NULL);
    }

    aws_array_list_clean_up(&scope->added_keys);

    return AWS_OP_SUCCESS;
}

int aws_endpoints_rule_engine_resolve(
    struct aws_endpoints_rule_engine *engine,
    const struct aws_endpoints_request_context *context,
    struct aws_endpoints_resolved_endpoint **out_resolved_endpoint) {

    if (aws_array_list_length(&engine->ruleset->rules) == 0) {
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EMPTY_RULESET);
    }

    struct eval_scope scope;
    if (s_init_top_level_scope(engine->allocator, context, engine->ruleset, &scope)) {
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

                /* TODO: resolve other url type */
                if (s_resolve_templated_string(
                        engine->allocator, rule->rule_data.endpoint.url.template, &scope, &endpoint->r.endpoint.url)) {
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to resolve templated error.");
                    goto on_error;
                }

                if (rule->rule_data.endpoint.properties && s_resolve_templated_string(
                                                               engine->allocator,
                                                               rule->rule_data.endpoint.properties,
                                                               &scope,
                                                               &endpoint->r.endpoint.properties)) {
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to resolve templated error.");
                    goto on_error;
                }

                /* TODO: headers */

                *out_resolved_endpoint = endpoint;
                goto on_success;
            }
            case AWS_ENDPOINTS_RULE_ERROR: {
                struct aws_endpoints_resolved_endpoint *error = s_endpoints_resolved_endpoint_new(engine->allocator);
                /* TODO: resolve other error types */
                if (s_resolve_templated_string(
                        engine->allocator, rule->rule_data.error.error.template, &scope, &error->r.error)) {
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to resolve templated error.");
                    goto on_error;
                }

                *out_resolved_endpoint = error;
                goto on_success;
            }
            case AWS_ENDPOINTS_RULE_TREE: {
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

        ++scope.rule_idx;
    }

    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "All rules have been exhausted.");
    aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RULESET_EXHAUSTED);
    goto on_error;

on_success:
    AWS_LOGF_DEBUG(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Successfully resolved endpoint.");
    s_scope_clean_up(engine->allocator, &scope);
    return AWS_OP_SUCCESS;

on_error:
    AWS_LOGF_DEBUG(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Unsuccessfully resolved endpoint.");
    s_scope_clean_up(engine->allocator, &scope);
    return AWS_OP_ERR;
}
