/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/array_list.h>
#include <aws/common/hash_table.h>
#include <aws/common/json.h>
#include <aws/common/string.h>
#include <aws/sdkutils/private/endpoints_regex.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>
#include <aws/sdkutils/private/endpoints_util.h>

void s_endpoints_value_clean_up_cb(void *value);

uint64_t aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_LAST];

void aws_endpoints_rule_engine_init(void) {
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_IS_SET] = aws_hash_c_string("isSet");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_NOT] = aws_hash_c_string("not");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_GET_ATTR] = aws_hash_c_string("getAttr");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_SUBSTRING] = aws_hash_c_string("substring");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_STRING_EQUALS] = aws_hash_c_string("stringEquals");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_BOOLEAN_EQUALS] = aws_hash_c_string("booleanEquals");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_COALESCE] = aws_hash_c_string("coalesce");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_SPLIT] = aws_hash_c_string("split");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_ITE] = aws_hash_c_string("ite");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_COALESCE] = aws_hash_c_string("coalesce");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_URI_ENCODE] = aws_hash_c_string("uriEncode");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_PARSE_URL] = aws_hash_c_string("parseURL");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_IS_VALID_HOST_LABEL] = aws_hash_c_string("isValidHostLabel");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_AWS_PARTITION] = aws_hash_c_string("aws.partition");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_AWS_PARSE_ARN] = aws_hash_c_string("aws.parseArn");
    aws_endpoints_fn_name_hash[AWS_ENDPOINTS_FN_AWS_IS_VIRTUAL_HOSTABLE_S3_BUCKET] =
        aws_hash_c_string("aws.isVirtualHostableS3Bucket");
}

static void s_on_condition_array_element_clean_up(void *element) {
    struct aws_endpoints_condition *condition = element;
    aws_endpoints_condition_clean_up(condition);
}

static void s_on_rule_array_element_clean_up(void *element) {
    struct aws_endpoints_rule *rule = element;
    aws_endpoints_rule_clean_up(rule);
}

static void s_on_expr_array_element_clean_up(void *element) {
    struct aws_endpoints_expr *expr = element;
    aws_endpoints_expr_clean_up(expr);
}

struct aws_partition_info *aws_partition_info_new(struct aws_allocator *allocator, struct aws_byte_cursor name) {
    AWS_PRECONDITION(allocator);
    struct aws_partition_info *partition_info = aws_mem_calloc(allocator, 1, sizeof(struct aws_partition_info));

    partition_info->allocator = allocator;
    partition_info->name = name;

    return partition_info;
}

void aws_partition_info_destroy(struct aws_partition_info *partition_info) {
    if (partition_info == NULL) {
        return;
    }

    if (!partition_info->is_copy) {
        aws_string_destroy(partition_info->info);
    }

    aws_endpoints_regex_destroy(partition_info->region_regex);

    aws_mem_release(partition_info->allocator, partition_info);
}

struct aws_endpoints_parameter *aws_endpoints_parameter_new(
    struct aws_allocator *allocator,
    struct aws_byte_cursor name) {
    AWS_PRECONDITION(allocator);
    struct aws_endpoints_parameter *parameter = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_parameter));

    parameter->allocator = allocator;
    parameter->name = name;

    return parameter;
}

void aws_endpoints_parameter_destroy(struct aws_endpoints_parameter *parameter) {
    if (parameter == NULL) {
        return;
    }

    if (parameter->has_default_value && parameter->type == AWS_ENDPOINTS_PARAMETER_STRING_ARRAY) {
        aws_array_list_deep_clean_up(&parameter->default_value.v.array, s_endpoints_value_clean_up_cb);
    }

    aws_mem_release(parameter->allocator, parameter);
}

void aws_endpoints_rule_clean_up(struct aws_endpoints_rule *rule) {
    AWS_PRECONDITION(rule);

    aws_array_list_deep_clean_up(&rule->conditions, s_on_condition_array_element_clean_up);

    switch (rule->type) {
        case AWS_ENDPOINTS_RULE_ENDPOINT:
            aws_endpoints_rule_data_endpoint_clean_up(&rule->rule_data.endpoint);
            break;
        case AWS_ENDPOINTS_RULE_ERROR:
            aws_endpoints_rule_data_error_clean_up(&rule->rule_data.error);
            break;
        case AWS_ENDPOINTS_RULE_TREE:
            aws_endpoints_rule_data_tree_clean_up(&rule->rule_data.tree);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }

    AWS_ZERO_STRUCT(*rule);
}

void aws_endpoints_rule_data_endpoint_clean_up(struct aws_endpoints_rule_data_endpoint *rule_data) {
    AWS_PRECONDITION(rule_data);

    aws_byte_buf_clean_up(&rule_data->properties);
    aws_hash_table_clean_up(&rule_data->headers);

    AWS_ZERO_STRUCT(*rule_data);
}

void aws_endpoints_rule_data_error_clean_up(struct aws_endpoints_rule_data_error *rule_data) {
    AWS_PRECONDITION(rule_data);

    AWS_ZERO_STRUCT(*rule_data);
}

void aws_endpoints_rule_data_tree_clean_up(struct aws_endpoints_rule_data_tree *rule_data) {
    AWS_PRECONDITION(rule_data);

    aws_array_list_deep_clean_up(&rule_data->rules, s_on_rule_array_element_clean_up);
    AWS_ZERO_STRUCT(*rule_data);
}

void aws_endpoints_condition_clean_up(struct aws_endpoints_condition *condition) {
    AWS_PRECONDITION(condition);

    AWS_ZERO_STRUCT(*condition);
}

void aws_endpoints_expr_clean_up(struct aws_endpoints_expr *expr) {
    AWS_PRECONDITION(expr);

    switch (expr->type) {
        case AWS_ENDPOINTS_EXPR_STRING:
        case AWS_ENDPOINTS_EXPR_BOOLEAN:
        case AWS_ENDPOINTS_EXPR_NUMBER:
        case AWS_ENDPOINTS_EXPR_REFERENCE:
            break;
        case AWS_ENDPOINTS_EXPR_FUNCTION:
            break;
        case AWS_ENDPOINTS_EXPR_ARRAY:
            break;
        case AWS_ENDPOINTS_EXPR_OBJECT:
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }

    AWS_ZERO_STRUCT(*expr);
}

struct aws_endpoints_scope_value *aws_endpoints_scope_value_new(
    struct aws_allocator *allocator,
    struct aws_byte_cursor name_cur) {
    AWS_PRECONDITION(allocator);
    struct aws_endpoints_scope_value *value = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_scope_value));

    value->allocator = allocator;
    value->name = aws_endpoints_non_owning_cursor_create(name_cur);

    return value;
}

void aws_endpoints_scope_value_destroy(struct aws_endpoints_scope_value *scope_value) {
    if (scope_value == NULL) {
        return;
    }
    aws_string_destroy(scope_value->name.string);

    aws_endpoints_value_clean_up(&scope_value->value);
    aws_mem_release(scope_value->allocator, scope_value);
}

void aws_endpoints_value_clean_up_cb(void *value);

void aws_endpoints_value_clean_up(struct aws_endpoints_value *aws_endpoints_value) {
    AWS_PRECONDITION(aws_endpoints_value);

    if (aws_endpoints_value->is_ref) {
        goto on_done;
    }

    if (aws_endpoints_value->type == AWS_ENDPOINTS_VALUE_STRING) {
        aws_string_destroy(aws_endpoints_value->v.owning_cursor_string.string);
    }

    if (aws_endpoints_value->type == AWS_ENDPOINTS_VALUE_OBJECT) {
        aws_string_destroy(aws_endpoints_value->v.owning_cursor_object.string);
    }

    if (aws_endpoints_value->type == AWS_ENDPOINTS_VALUE_ARRAY) {
        aws_array_list_deep_clean_up(&aws_endpoints_value->v.array, s_endpoints_value_clean_up_cb);
    }

on_done:
    AWS_ZERO_STRUCT(*aws_endpoints_value);
}

void s_endpoints_value_clean_up_cb(void *value) {
    struct aws_endpoints_value *aws_endpoints_value = value;
    aws_endpoints_value_clean_up(aws_endpoints_value);
}

int aws_endpoints_deep_copy_parameter_value(
    struct aws_allocator *allocator,
    const struct aws_endpoints_value *from,
    struct aws_endpoints_value *to) {

    to->type = from->type;
    to->is_ref = false;

    if (to->type == AWS_ENDPOINTS_VALUE_STRING) {
        to->v.owning_cursor_string =
            aws_endpoints_owning_cursor_from_cursor(allocator, from->v.owning_cursor_string.cur);
    } else if (to->type == AWS_ENDPOINTS_VALUE_BOOLEAN) {
        to->v.boolean = from->v.boolean;
    } else if (to->type == AWS_ENDPOINTS_VALUE_ARRAY) {
        size_t len = aws_array_list_length(&from->v.array);
        aws_array_list_init_dynamic(&to->v.array, allocator, len, sizeof(struct aws_endpoints_value));
        for (size_t i = 0; i < len; ++i) {
            struct aws_endpoints_value val;
            aws_array_list_get_at(&from->v.array, &val, i);

            struct aws_endpoints_value to_val;
            if (aws_endpoints_deep_copy_parameter_value(allocator, &val, &to_val)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Unexpected array element type.");
                goto on_error;
            }

            aws_array_list_set_at(&to->v.array, &to_val, i);
        }
    } else {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Unexpected value type.");
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_value_clean_up(to);
    return AWS_OP_ERR;
}

static int s_resolve_templated_value_with_pathing(
    struct aws_allocator *allocator,
    struct aws_endpoints_resolution_scope *scope,
    struct aws_byte_cursor template_cur,
    struct aws_owning_cursor *out_owning_cursor) {

    struct aws_endpoints_value resolved_value = {0};
    struct aws_byte_cursor split = {0};
    if (!aws_byte_cursor_next_split(&template_cur, '#', &split) || split.len == 0) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Invalid value in template string.");
        goto on_error;
    }

    struct aws_hash_element *elem = NULL;
    if (aws_hash_table_find(&scope->values, &split, &elem) || elem == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Templated value does not exist: " PRInSTR, AWS_BYTE_CURSOR_PRI(split));
        goto on_error;
    }

    struct aws_endpoints_scope_value *scope_value = elem->value;
    if (!aws_byte_cursor_next_split(&template_cur, '#', &split)) {
        if (scope_value->value.type != AWS_ENDPOINTS_VALUE_STRING) {
            AWS_LOGF_ERROR(
                AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Unexpected type: must be string if pathing is not provided");
            goto on_error;
        }

        *out_owning_cursor = aws_endpoints_non_owning_cursor_create(scope_value->value.v.owning_cursor_string.cur);
        return AWS_OP_SUCCESS;
    }

    if (scope_value->value.type == AWS_ENDPOINTS_VALUE_OBJECT) {
        if (aws_endpoints_path_through_object(allocator, &scope_value->value, split, &resolved_value)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to path through object.");
            goto on_error;
        }
    } else if (scope_value->value.type == AWS_ENDPOINTS_VALUE_ARRAY) {
        if (aws_endpoints_path_through_array(allocator, scope, &scope_value->value, split, &resolved_value)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to path through array.");
            goto on_error;
        }
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE,
            "Invalid value type for pathing through. type %d",
            scope_value->value.type);
        goto on_error;
    }

    if (resolved_value.type != AWS_ENDPOINTS_VALUE_STRING) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Templated string didn't resolve to string");
        goto on_error;
    }

    if (resolved_value.v.owning_cursor_string.string != NULL) {
        /* Transfer ownership of the underlying string. */
        *out_owning_cursor = aws_endpoints_owning_cursor_from_string(resolved_value.v.owning_cursor_string.string);
        resolved_value.v.owning_cursor_string.string = NULL;
    } else {
        /* Unlikely to get here since current pathing always return new string. */
        *out_owning_cursor = aws_endpoints_non_owning_cursor_create(resolved_value.v.owning_cursor_string.cur);
    }

    aws_endpoints_value_clean_up(&resolved_value);

    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_value_clean_up(&resolved_value);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
}

int aws_endpoints_resolve_template(struct aws_byte_cursor template, void *user_data, struct aws_owning_cursor *out_cursor) {

    struct resolve_template_callback_data *data = user_data;

    if (s_resolve_templated_value_with_pathing(data->allocator, data->scope, template, out_cursor)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve template value.");
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
        ;
    }

    return AWS_OP_SUCCESS;
}

int aws_endpoints_resolve_expr(
    struct aws_allocator *allocator,
    uint16_t expr_ref,
    struct aws_endpoints_resolution_scope *scope,
    struct aws_endpoints_value *out_value) {

    struct aws_endpoints_expr *expr;
    if (aws_array_list_get_at_ptr(&scope->expr_index, (void **)&expr, expr_ref)) {
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
    }

    AWS_ZERO_STRUCT(*out_value);
    switch (expr->type) {
        case AWS_ENDPOINTS_EXPR_TEMPLATE_STRING: {
            struct aws_byte_buf buf;
            struct resolve_template_callback_data data = {.allocator = allocator, .scope = scope};
            if (aws_byte_buf_init_from_resolved_templated_string(
                    allocator, &buf, expr->e.string, aws_endpoints_resolve_template, &data, false)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve templated string.");
                goto on_error;
            }

            out_value->type = AWS_ENDPOINTS_VALUE_STRING;
            out_value->v.owning_cursor_string =
                aws_endpoints_owning_cursor_from_string(aws_string_new_from_buf(allocator, &buf));
            aws_byte_buf_clean_up(&buf);
            break;
        }
        case AWS_ENDPOINTS_EXPR_STRING: {
            out_value->type = AWS_ENDPOINTS_VALUE_STRING;
            out_value->v.owning_cursor_string = aws_endpoints_non_owning_cursor_create(expr->e.string);
            out_value->is_ref = true;
            break;
        }
        case AWS_ENDPOINTS_EXPR_BOOLEAN: {
            out_value->type = AWS_ENDPOINTS_VALUE_BOOLEAN;
            out_value->v.boolean = expr->e.boolean;
            break;
        }
        case AWS_ENDPOINTS_EXPR_NUMBER: {
            out_value->type = AWS_ENDPOINTS_VALUE_NUMBER;
            out_value->v.number = expr->e.number;
            break;
        }
        case AWS_ENDPOINTS_EXPR_ARRAY: {
            out_value->type = AWS_ENDPOINTS_VALUE_ARRAY;
            {
                size_t len = expr->e.array.len;
                aws_array_list_init_dynamic(&out_value->v.array, allocator, len, sizeof(struct aws_endpoints_value));
                for (size_t i = 0; i < len; ++i) {
                    struct aws_endpoints_value val;
                    if (aws_endpoints_resolve_expr(allocator, expr->e.array.ptr[i], scope, &val)) {
                        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve array element.");
                        aws_endpoints_value_clean_up(out_value);
                        goto on_error;
                    }
                    aws_array_list_set_at(&out_value->v.array, &val, i);
                }
            }
            break;
        }
        case AWS_ENDPOINTS_EXPR_REFERENCE: {
            struct aws_hash_element *element;
            if (aws_hash_table_find(&scope->values, &expr->e.reference, &element)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to deref.");
                goto on_error;
            }

            if (element == NULL) {
                out_value->type = AWS_ENDPOINTS_VALUE_NONE;
            } else {
                struct aws_endpoints_scope_value *aws_endpoints_scope_value = element->value;

                *out_value = aws_endpoints_scope_value->value;
                out_value->is_ref = true;
            }
            break;
        }
        case AWS_ENDPOINTS_EXPR_FUNCTION: {
            if (aws_endpoints_dispatch_standard_lib_fn_resolve(
                    expr->e.function.fn, allocator, expr->e.function.args, scope, out_value)) {
                goto on_error;
            }
            break;
        }
        case AWS_ENDPOINTS_EXPR_OBJECT: {
            /* Object expressions are only used by the BDD engine, not the v1.0 tree engine. */
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Object expressions are not supported in v1.0 engine.");
            goto on_error;
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
}

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

struct aws_endpoints_resolved_endpoint *aws_endpoints_resolved_endpoint_new(struct aws_allocator *allocator) {
    AWS_PRECONDITION(allocator);

    struct aws_endpoints_resolved_endpoint *resolved =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_resolved_endpoint));
    resolved->allocator = allocator;

    aws_ref_count_init(&resolved->ref_count, resolved, s_endpoints_resolved_endpoint_destroy);

    return resolved;
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

int aws_endpoints_resolve_headers(
    struct aws_allocator *allocator,
    struct aws_endpoints_resolution_scope *scope,
    struct aws_hash_table *headers,
    struct aws_hash_table *out_headers) {

    struct aws_endpoints_value value;
    struct aws_array_list *resolved_headers = NULL;

    if (aws_hash_table_init(
            out_headers,
            allocator,
            aws_hash_table_get_entry_count(headers),
            aws_hash_string,
            aws_hash_callback_string_eq,
            aws_hash_callback_string_destroy,
            s_callback_headers_destroy)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to init table for resolved headers");
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
            uint16_t ref;
            if (aws_array_list_get_at(header_list, &ref, i)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to get header.");
                goto on_error;
            }

            if (aws_endpoints_resolve_expr(allocator, ref, scope, &value) || value.type != AWS_ENDPOINTS_VALUE_STRING) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve header expr.");
                goto on_error;
            }

            struct aws_string *str = aws_string_new_from_cursor(allocator, &value.v.owning_cursor_string.cur);
            if (aws_array_list_push_back(resolved_headers, &str)) {
                aws_string_destroy(str);
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to add resolved header to result.");
                goto on_error;
            }

            aws_endpoints_value_clean_up(&value);
        }

        if (aws_hash_table_put(out_headers, aws_string_clone_or_reuse(allocator, key), resolved_headers, NULL)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to add resolved header to result.");
            goto on_error;
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_value_clean_up(&value);
    if (resolved_headers != NULL) {
        s_callback_headers_destroy(resolved_headers);
    }
    aws_hash_table_clean_up(out_headers);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
}

AWS_STATIC_ASSERT(AWS_ENDPOINTS_VALUE_SIZE == 7);
bool aws_endpoints_is_value_truthy(const struct aws_endpoints_value *value) {
    switch (value->type) {
        case AWS_ENDPOINTS_VALUE_NONE:
            return false;
        case AWS_ENDPOINTS_VALUE_BOOLEAN:
            return value->v.boolean;
        case AWS_ENDPOINTS_VALUE_ARRAY:
        case AWS_ENDPOINTS_VALUE_STRING:
        case AWS_ENDPOINTS_VALUE_OBJECT:
            return true;
        case AWS_ENDPOINTS_VALUE_NUMBER:
            return value->v.number != 0;
        default:
            AWS_ASSERT(false);
            return false;
    }
}

int aws_endpoints_argv_expect(
    struct aws_allocator *allocator,
    struct aws_endpoints_resolution_scope *scope,
    struct aws_endpoints_args args,
    size_t idx,
    enum aws_endpoints_value_type expected_type,
    struct aws_endpoints_value *out_value) {

    AWS_ZERO_STRUCT(*out_value);
    struct aws_endpoints_value argv_value = {0};
    
    if (idx >= args.argc) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to parse argv");
        goto on_error;
    }

    uint16_t expr_ref = args.argv[idx];

    if (aws_endpoints_resolve_expr(allocator, expr_ref, scope, &argv_value)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to resolve argv.");
        goto on_error;
    }

    if (expected_type != AWS_ENDPOINTS_VALUE_ANY && argv_value.type != expected_type) {
        AWS_LOGF_ERROR(
            AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE,
            "Unexpected arg type actual: %u expected %u.",
            argv_value.type,
            expected_type);
        goto on_error;
    }

    *out_value = argv_value;
    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_value_clean_up(&argv_value);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_RESOLVE_FAILED);
}
