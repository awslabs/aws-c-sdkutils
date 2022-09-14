/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/array_list.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/sdkutils/private/endpoints_ruleset_types_impl.h>

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

void aws_array_list_deep_clean_up(struct aws_array_list *array, aws_array_callback_clean_up_fn on_clean_up_element) {
    for (size_t idx = 0; idx < aws_array_list_length(array); ++idx) {
        void *element = NULL;

        aws_array_list_get_at_ptr(array, &element, idx);
        AWS_ASSERT(element);
        on_clean_up_element(element);
    }
    aws_array_list_clean_up(array);
}

struct aws_endpoints_parameter *aws_endpoints_parameter_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *name_cur) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(name_cur);
    struct aws_endpoints_parameter *parameter = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_parameter));

    parameter->allocator = allocator;
    parameter->name = aws_string_new_from_cursor(allocator, name_cur);
    parameter->name_cur = aws_byte_cursor_from_string(parameter->name);

    return parameter;
}

void aws_endpoints_parameter_destroy(struct aws_endpoints_parameter *parameter) {
    if (parameter == NULL) {
        return;
    }

    aws_string_destroy(parameter->name);
    aws_string_destroy(parameter->built_in);
    if (parameter->type == AWS_ENDPOINTS_PARAMETER_STRING) {
        aws_string_destroy(parameter->default_value.string);
    }
    aws_string_destroy(parameter->documentation);
    aws_string_destroy(parameter->deprecated_message);
    aws_string_destroy(parameter->deprecated_since);

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

    aws_string_destroy(rule->documentation);
    AWS_ZERO_STRUCT(*rule);
}

void aws_endpoints_rule_data_endpoint_clean_up(struct aws_endpoints_rule_data_endpoint *rule_data) {
    AWS_PRECONDITION(rule_data);

    switch (rule_data->url_type) {
        case AWS_ENDPOINTS_URL_TEMPLATE:
            aws_string_destroy(rule_data->url.template);
            break;
        case AWS_ENDPOINTS_URL_REFERENCE:
            aws_string_destroy(rule_data->url.reference);
            break;
        case AWS_ENDPOINTS_URL_FUNCTION:
            aws_endpoints_function_clean_up(&rule_data->url.function);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }

    aws_string_destroy(rule_data->properties);
    aws_hash_table_clean_up(&rule_data->headers);

    AWS_ZERO_STRUCT(*rule_data);
}

void aws_endpoints_rule_data_error_clean_up(struct aws_endpoints_rule_data_error *rule_data) {
    AWS_PRECONDITION(rule_data);

    switch (rule_data->error_type) {
        case AWS_ENDPOINTS_ERROR_TEMPLATE:
            aws_string_destroy(rule_data->error.template);
            break;
        case AWS_ENDPOINTS_ERROR_REFERENCE:
            aws_string_destroy(rule_data->error.reference);
            break;
        case AWS_ENDPOINTS_ERROR_FUNCTION:
            aws_endpoints_function_clean_up(&rule_data->error.function);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }
    AWS_ZERO_STRUCT(*rule_data);
}

void aws_endpoints_rule_data_tree_clean_up(struct aws_endpoints_rule_data_tree *rule_data) {
    AWS_PRECONDITION(rule_data);

    aws_array_list_deep_clean_up(&rule_data->rules, s_on_rule_array_element_clean_up);
    AWS_ZERO_STRUCT(*rule_data);
}

void aws_endpoints_condition_clean_up(struct aws_endpoints_condition *condition) {
    AWS_PRECONDITION(condition);

    aws_string_destroy(condition->assign);
    aws_endpoints_function_clean_up(&condition->function);
    AWS_ZERO_STRUCT(*condition);
}

void aws_endpoints_function_clean_up(struct aws_endpoints_function *function) {
    AWS_PRECONDITION(function);

    aws_string_destroy(function->fn);
    function->fn = NULL;

    aws_array_list_deep_clean_up(&function->argv, s_on_expr_array_element_clean_up);
    AWS_ZERO_STRUCT(*function);
}

void aws_endpoints_expr_clean_up(struct aws_endpoints_expr *expr) {
    AWS_PRECONDITION(expr);

    switch (expr->type) {
        case AWS_ENDPOINTS_EXPR_STRING:
            aws_string_destroy(expr->e.string);
            break;
        case AWS_ENDPOINTS_EXPR_BOOLEAN:
        case AWS_ENDPOINTS_EXPR_NUMBER:
            break;
        case AWS_ENDPOINTS_EXPR_FUNCTION:
            aws_endpoints_function_clean_up(&expr->e.function);
            break;
        case AWS_ENDPOINTS_EXPR_REFERENCE:
            aws_string_destroy(expr->e.reference);
            break;
        case AWS_ENDPOINTS_EXPR_ARRAY:
            aws_array_list_deep_clean_up(&expr->e.array, s_on_expr_array_element_clean_up);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }

    AWS_ZERO_STRUCT(*expr);
}
