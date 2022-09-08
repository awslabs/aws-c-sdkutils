/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/array_list.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/sdkutils/endpoints/private/ruleset_types_impl.h>

static void s_on_condition_array_element_destroy(void *element) {
    struct aws_endpoints_condition *condition = element;
    aws_endpoints_condition_destroy(condition);
}

static void s_on_rule_array_element_destroy(void *element) {
    struct aws_endpoints_rule *rule = element;
    aws_endpoints_rule_destroy(rule);
}

static void s_on_expr_array_element_destroy(void *element) {
    struct aws_endpoints_expr *expr = element;
    aws_endpoints_expr_destroy(expr);
}

void aws_array_list_deep_cleanup(struct aws_array_list *array, aws_array_callback_destroy_fn on_destroy_element) {
    for (size_t idx = 0; idx < aws_array_list_length(array); ++idx) {
        void *element = NULL;

        int error_code = aws_array_list_get_at(array, &element, idx);
        AWS_ASSERT(error_code == AWS_OP_SUCCESS);
        AWS_ASSERT(element);
        on_destroy_element(element);
    }
    aws_array_list_clean_up(array);
}

struct aws_endpoints_parameter *aws_endpoints_parameter_new(
    struct aws_allocator *allocator,
    enum aws_endpoints_parameter_value_type type,
    struct aws_string *documentation) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(documentation);
    struct aws_endpoints_parameter *parameter = aws_mem_acquire(allocator, sizeof(struct aws_endpoints_parameter));
    AWS_ZERO_STRUCT(*parameter);

    parameter->allocator = allocator;
    parameter->type = type;
    parameter->documentation = documentation;

    return parameter;
}

void aws_endpoints_parameter_destroy(struct aws_endpoints_parameter *parameter) {
    aws_string_destroy(parameter->built_in);
    if (parameter->type == AWS_ENDPOINTS_PARAMETER_STRING) {
        aws_string_destroy(parameter->default_value.string);
    }
    aws_string_destroy(parameter->documentation);
    aws_string_destroy(parameter->deprecated_message);
    aws_string_destroy(parameter->deprecated_since);

    aws_mem_release(parameter->allocator, parameter);
}

struct aws_endpoints_rule *aws_endpoints_rule_new(struct aws_allocator *allocator, enum aws_endpoints_rule_type type) {

    struct aws_endpoints_rule *rule = aws_mem_acquire(allocator, sizeof(struct aws_endpoints_rule));
    AWS_ZERO_STRUCT(*rule);

    rule->allocator = allocator;
    rule->type = type;

    return rule;
}

void aws_endpoints_rule_destroy(struct aws_endpoints_rule *rule) {
    aws_array_list_deep_cleanup(&rule->conditions, s_on_condition_array_element_destroy);

    switch (rule->type) {
        case AWS_ENDPOINTS_RULE_ENDPOINT:
            aws_endpoints_rule_data_endpoint_destroy(rule->rule_data.endpoint);
            break;
        case AWS_ENDPOINTS_RULE_ERROR:
            aws_endpoints_rule_data_error_destroy(rule->rule_data.error);
            break;
        case AWS_ENDPOINTS_RULE_TREE:
            aws_endpoints_rule_data_tree_destroy(rule->rule_data.tree);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }

    aws_string_destroy(rule->documentation);

    aws_mem_release(rule->allocator, rule);
}

struct aws_endpoints_rule_data_endpoint *aws_endpoints_rule_data_endpoint_new(struct aws_allocator *allocator) {
    struct aws_endpoints_rule_data_endpoint *rule_data =
        aws_mem_acquire(allocator, sizeof(struct aws_endpoints_rule_data_endpoint));
    AWS_ZERO_STRUCT(*rule_data);
    rule_data->allocator = allocator;

    return rule_data;
}

void aws_endpoints_rule_data_endpoint_destroy(struct aws_endpoints_rule_data_endpoint *rule_data) {

    switch (rule_data->url_type) {
        case AWS_ENDPOINTS_URL_TEMPLATE:
            aws_string_destroy(rule_data->url.template);
            break;
        case AWS_ENDPOINTS_URL_REFERENCE:
            aws_endpoints_reference_destroy(rule_data->url.reference);
            break;
        case AWS_ENDPOINTS_URL_FUNCTION:
            aws_endpoints_function_destroy(rule_data->url.function);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }

    aws_string_destroy(rule_data->properties);
    if (rule_data->headers) {
        aws_hash_table_clean_up(rule_data->headers);
        aws_mem_release(rule_data->allocator, rule_data->headers);
    }
    aws_mem_release(rule_data->allocator, rule_data);
}

struct aws_endpoints_rule_data_error *aws_endpoints_rule_data_error_new(struct aws_allocator *allocator) {
    struct aws_endpoints_rule_data_error *rule_data =
        aws_mem_acquire(allocator, sizeof(struct aws_endpoints_rule_data_error));
    AWS_ZERO_STRUCT(*rule_data);
    rule_data->allocator = allocator;
    return rule_data;
}

void aws_endpoints_rule_data_error_destroy(struct aws_endpoints_rule_data_error *rule_data) {
    switch (rule_data->error_type) {
        case AWS_ENDPOINTS_ERROR_TEMPLATE:
            aws_string_destroy(rule_data->error.template);
            break;
        case AWS_ENDPOINTS_ERROR_REFERENCE:
            aws_endpoints_reference_destroy(rule_data->error.reference);
            break;
        case AWS_ENDPOINTS_ERROR_FUNCTION:
            aws_endpoints_function_destroy(rule_data->error.function);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }
    aws_mem_release(rule_data->allocator, rule_data);
}

struct aws_endpoints_rule_data_tree *aws_endpoints_rule_data_tree_new(struct aws_allocator *allocator) {
    AWS_PRECONDITION(allocator);
    struct aws_endpoints_rule_data_tree *rule_data =
        aws_mem_acquire(allocator, sizeof(struct aws_endpoints_rule_data_tree));
    AWS_ZERO_STRUCT(*rule_data);
    rule_data->allocator = allocator;
    return rule_data;
}

void aws_endpoints_rule_data_tree_destroy(struct aws_endpoints_rule_data_tree *rule_data) {
    aws_array_list_deep_cleanup(&rule_data->rules, s_on_rule_array_element_destroy);

    aws_mem_release(rule_data->allocator, rule_data);
}

struct aws_endpoints_condition *aws_endpoints_condition_new(
    struct aws_allocator *allocator,
    struct aws_endpoints_function *function) {
    AWS_PRECONDITION(function);

    struct aws_endpoints_condition *condition = aws_mem_acquire(allocator, sizeof(struct aws_endpoints_condition));
    AWS_ZERO_STRUCT(*condition);
    condition->allocator = allocator;
    condition->function = function;

    return condition;
}

void aws_endpoints_condition_destroy(struct aws_endpoints_condition *condition) {

    aws_string_destroy(condition->assign);
    aws_endpoints_function_destroy(condition->function);

    aws_mem_release(condition->allocator, condition);
}

struct aws_endpoints_function *aws_endpoints_function_new(struct aws_allocator *allocator, struct aws_string *fn) {
    AWS_PRECONDITION(fn);

    struct aws_endpoints_function *function = aws_mem_acquire(allocator, sizeof(struct aws_endpoints_function));
    AWS_ZERO_STRUCT(*function);
    function->allocator = allocator;
    function->fn = fn;

    return function;
}

void aws_endpoints_function_destroy(struct aws_endpoints_function *function) {
    aws_string_destroy(function->fn);

    aws_array_list_deep_cleanup(&function->argv, s_on_expr_array_element_destroy);

    aws_mem_release(function->allocator, function);
}

struct aws_endpoints_expr *aws_endpoints_expr_new(struct aws_allocator *allocator, enum aws_endpoints_expr_type type) {
    struct aws_endpoints_expr *expr = aws_mem_acquire(allocator, sizeof(struct aws_endpoints_expr));
    AWS_ZERO_STRUCT(*expr);
    expr->allocator = allocator;
    expr->type = type;

    return expr;
}

void aws_endpoints_expr_destroy(struct aws_endpoints_expr *expr) {
    switch (expr->type) {
        case AWS_ENDPOINTS_EXPR_STRING:
            aws_string_destroy(expr->e.string);
            break;
        case AWS_ENDPOINTS_EXPR_BOOLEAN:
        case AWS_ENDPOINTS_EXPR_NUMBER:
            break;
        case AWS_ENDPOINTS_EXPR_FUNCTION:
            aws_endpoints_function_destroy(expr->e.function);
            break;
        case AWS_ENDPOINTS_EXPR_REFERENCE:
            aws_endpoints_reference_destroy(expr->e.reference);
            break;
        case AWS_ENDPOINTS_EXPR_ARRAY:
            aws_array_list_deep_cleanup(&expr->e.array, s_on_expr_array_element_destroy);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }

    aws_mem_release(expr->allocator, expr);
}

struct aws_endpoints_reference *aws_endpoints_reference_new(struct aws_allocator *allocator, struct aws_string *ref) {
    AWS_PRECONDITION(ref);
    struct aws_endpoints_reference *reference = aws_mem_acquire(allocator, sizeof(struct aws_endpoints_reference));
    AWS_ZERO_STRUCT(*reference);
    reference->allocator = allocator;
    reference->ref = ref;

    return reference;
}

void aws_endpoints_reference_destroy(struct aws_endpoints_reference *reference) {
    aws_string_destroy(reference->ref);
    aws_mem_release(reference->allocator, reference);
}
