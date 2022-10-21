/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/json.h>
#include <aws/common/uri.h>
#include <aws/common/string.h>

#include <aws/sdkutils/resource_name.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>
#include <aws/sdkutils/private/endpoints_util.h>

static struct aws_byte_cursor s_scheme_http = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("http");
static struct aws_byte_cursor s_scheme_https = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("https");

static int s_eval_fn_is_set(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {

    struct eval_value argv_value;
    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_ANY, &argv_value)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval args for isSet.");
        goto on_error;
    }

    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
    out_value->v.boolean = argv_value.type != AWS_ENDPOINTS_EVAL_VALUE_NONE;

    aws_endpoints_eval_value_clean_up(&argv_value);
    return AWS_OP_SUCCESS;

on_error:
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_eval_fn_not(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {

    struct eval_value argv_value;
    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN, &argv_value)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval args for not.");
        goto on_error;
    }

    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
    out_value->v.boolean = !argv_value.v.boolean;

    aws_endpoints_eval_value_clean_up(&argv_value);
    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_eval_value_clean_up(&argv_value);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_eval_fn_get_attr(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {

    struct eval_value argv_value;
    struct eval_value argv_path;
    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_ANY, &argv_value) ||
        aws_endpoints_argv_expect(allocator, scope, argv, 1, AWS_ENDPOINTS_EVAL_VALUE_STRING, &argv_path)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval args for get attr.");
        goto on_error;
    }

    struct aws_byte_cursor path_cur = argv_path.v.string.cur;

    if (argv_value.type == AWS_ENDPOINTS_EVAL_VALUE_OBJECT) {
        if (aws_endpoints_path_through_object(allocator, &argv_value, path_cur, out_value)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to path through object.");
            goto on_error;
        }
    } else if (argv_value.type == AWS_ENDPOINTS_EVAL_VALUE_ARRAY) {
        if (aws_endpoints_path_through_array(allocator, scope, &argv_value, path_cur, out_value)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to path through array.");
            goto on_error;
        }
    } else {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Invalid value type for pathing through.");
        goto on_error;
    }

    aws_endpoints_eval_value_clean_up(&argv_value);
    aws_endpoints_eval_value_clean_up(&argv_path);

    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_eval_value_clean_up(&argv_value);
    aws_endpoints_eval_value_clean_up(&argv_path);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_eval_fn_substring(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {
    struct eval_value input_value;
    struct eval_value start_value;
    struct eval_value stop_value;
    struct eval_value reverse_value;
    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_STRING, &input_value) ||
        aws_endpoints_argv_expect(allocator, scope, argv, 1, AWS_ENDPOINTS_EVAL_VALUE_NUMBER, &start_value) ||
        aws_endpoints_argv_expect(allocator, scope, argv, 2, AWS_ENDPOINTS_EVAL_VALUE_NUMBER, &stop_value) ||
        aws_endpoints_argv_expect(allocator, scope, argv, 3, AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN, &reverse_value)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval args for substring.");
        goto on_error;
    }

    if (start_value.v.number >= stop_value.v.number || input_value.v.string.cur.len < stop_value.v.number) {
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;

        goto on_success;
    }

    for (size_t idx = 0; idx < input_value.v.string.cur.len; ++idx) {
        if (input_value.v.string.cur.ptr[idx] > 127) {
            out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;

            goto on_success;
        }
    }

    if (!reverse_value.v.boolean) {
        size_t start = (size_t)start_value.v.number;
        size_t end = (size_t)stop_value.v.number;
        struct aws_byte_cursor substring = {.ptr = input_value.v.string.cur.ptr + start, .len = end - start};

        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_STRING;
        out_value->v.string = aws_endpoints_owning_cursor_create(aws_string_new_from_cursor(allocator, &substring));
        goto on_success;
    } else {
        size_t r_start = input_value.v.string.cur.len - (size_t)stop_value.v.number;
        size_t r_stop = input_value.v.string.cur.len - (size_t)start_value.v.number;

        struct aws_byte_cursor substring = {.ptr = input_value.v.string.cur.ptr + r_start, .len = r_stop - r_start};
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_STRING;
        out_value->v.string = aws_endpoints_owning_cursor_create(aws_string_new_from_cursor(allocator, &substring));
        goto on_success;
    }

on_success:
    aws_endpoints_eval_value_clean_up(&input_value);
    aws_endpoints_eval_value_clean_up(&start_value);
    aws_endpoints_eval_value_clean_up(&stop_value);
    aws_endpoints_eval_value_clean_up(&reverse_value);
    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_eval_value_clean_up(&input_value);
    aws_endpoints_eval_value_clean_up(&start_value);
    aws_endpoints_eval_value_clean_up(&stop_value);
    aws_endpoints_eval_value_clean_up(&reverse_value);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_eval_fn_string_equals(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {

    struct eval_value argv_value_1;
    struct eval_value argv_value_2;
    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_STRING, &argv_value_1) ||
        aws_endpoints_argv_expect(allocator, scope, argv, 1, AWS_ENDPOINTS_EVAL_VALUE_STRING, &argv_value_2)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval stringEquals.");
        goto on_error;
    }

    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
    out_value->v.boolean = aws_byte_cursor_eq(&argv_value_1.v.string.cur, &argv_value_2.v.string.cur);

    aws_endpoints_eval_value_clean_up(&argv_value_1);
    aws_endpoints_eval_value_clean_up(&argv_value_2);
    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_eval_value_clean_up(&argv_value_1);
    aws_endpoints_eval_value_clean_up(&argv_value_2);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_eval_fn_boolean_equals(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {

    struct eval_value argv_value_1;
    struct eval_value argv_value_2;
    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN, &argv_value_1) ||
        aws_endpoints_argv_expect(allocator, scope, argv, 1, AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN, &argv_value_2)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval booleanEquals.");
        goto on_error;
    }

    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
    out_value->v.boolean = argv_value_1.v.boolean == argv_value_2.v.boolean;
    aws_endpoints_eval_value_clean_up(&argv_value_1);
    aws_endpoints_eval_value_clean_up(&argv_value_2);

    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_eval_value_clean_up(&argv_value_1);
    aws_endpoints_eval_value_clean_up(&argv_value_2);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_eval_fn_uri_encode(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {

    struct aws_byte_buf buf;
    struct eval_value argv_value;
    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_STRING, &argv_value)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval parameter to uri encode.");
        goto on_error;
    }

    if (aws_byte_buf_init(&buf, allocator, 10)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval parameter to uri encode.");
        goto on_error;
    }

    if (aws_byte_buf_append_encoding_uri_param(&buf, &argv_value.v.string.cur)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to uri encode value.");
        aws_byte_buf_clean_up(&buf);
        goto on_error;
    }

    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_STRING;
    out_value->v.string = aws_endpoints_owning_cursor_create(aws_string_new_from_buf(allocator, &buf));

    aws_endpoints_eval_value_clean_up(&argv_value);
    aws_byte_buf_clean_up(&buf);

    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_eval_value_clean_up(&argv_value);
    aws_byte_buf_clean_up(&buf);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static bool s_is_uri_ip(struct aws_byte_cursor host, bool is_uri_encoded) {
    return aws_is_ipv4(host) || aws_is_ipv6(host, is_uri_encoded);
}

static int s_eval_fn_parse_url(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {

    struct aws_uri uri;
    struct aws_json_value *root = NULL;
    struct eval_value argv_url;
    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_STRING, &argv_url)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval args for parse url.");
        goto on_error;
    }

    if (aws_uri_init_parse(&uri, allocator, &argv_url.v.string.cur)) {
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;
        goto on_success;
    }

    if (aws_uri_query_string(&uri)->len > 0) {
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;
        goto on_success;
    }

    const struct aws_byte_cursor *scheme = aws_uri_scheme(&uri);
    AWS_ASSERT(scheme != NULL);

    root = aws_json_value_new_object(allocator);

    if (scheme->len == 0) {
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;
        goto on_success;
    }

    if (!(aws_byte_cursor_eq(scheme, &s_scheme_http) || aws_byte_cursor_eq(scheme, &s_scheme_https))) {
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;
        goto on_success;
    }

    if (aws_json_value_add_to_object(
            root, aws_byte_cursor_from_c_str("scheme"), aws_json_value_new_string(allocator, *scheme))) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to add scheme to object.");
        goto on_error;
    }

    const struct aws_byte_cursor *authority = aws_uri_authority(&uri);
    AWS_ASSERT(authority != NULL);

    if (authority->len == 0) {
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;
        goto on_success;
    }

    if (aws_json_value_add_to_object(
            root, aws_byte_cursor_from_c_str("authority"), aws_json_value_new_string(allocator, *authority))) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to add authority to object.");
        goto on_error;
    }

    const struct aws_byte_cursor *path = aws_uri_path(&uri);

    if (aws_json_value_add_to_object(
            root, aws_byte_cursor_from_c_str("path"), aws_json_value_new_string(allocator, *path))) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to add path to object.");
        goto on_error;
    }

    struct aws_byte_cursor normalized_path_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("normalizedPath");
    struct aws_byte_buf normalized_path_buf;
    if (aws_byte_buf_init_from_normalized_uri_path(allocator, *path, &normalized_path_buf) ||
        aws_json_value_add_to_object(
            root,
            normalized_path_cur,
            aws_json_value_new_string(allocator, aws_byte_cursor_from_buf(&normalized_path_buf)))) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to normalize path.");
        aws_byte_buf_clean_up(&normalized_path_buf);
        goto on_error;
    }

    aws_byte_buf_clean_up(&normalized_path_buf);

    const struct aws_byte_cursor *host_name = aws_uri_host_name(&uri);
    bool is_ip = s_is_uri_ip(*host_name, true);
    if (aws_json_value_add_to_object(
            root, aws_byte_cursor_from_c_str("isIp"), aws_json_value_new_boolean(allocator, is_ip))) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to add isIp to object.");
        goto on_error;
    }

    struct aws_byte_buf buf;
    if (aws_byte_buf_init(&buf, allocator, 0)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed init buffer for parseUrl return.");
        aws_byte_buf_clean_up(&buf);
        goto on_error;
    }

    if (aws_byte_buf_append_json_string(root, &buf)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to create JSON object.");
        aws_byte_buf_clean_up(&buf);
        goto on_error;
    }

    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_OBJECT;
    out_value->v.object = aws_endpoints_owning_cursor_create(aws_string_new_from_buf(allocator, &buf));

    aws_byte_buf_clean_up(&buf);

on_success:
    aws_uri_clean_up(&uri);
    aws_endpoints_eval_value_clean_up(&argv_url);
    aws_json_value_destroy(root);

    return AWS_OP_SUCCESS;

on_error:
    aws_uri_clean_up(&uri);
    aws_endpoints_eval_value_clean_up(&argv_url);
    aws_json_value_destroy(root);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_eval_is_valid_host_label(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {

    struct eval_value argv_value;
    struct eval_value argv_allow_subdomains;
    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_STRING, &argv_value) ||
        aws_endpoints_argv_expect(allocator, scope, argv, 1, AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN, &argv_allow_subdomains)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval not.");
        goto on_error;
    }

    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
    out_value->v.boolean = aws_is_valid_host_label(argv_value.v.string.cur, argv_allow_subdomains.v.boolean);

    aws_endpoints_eval_value_clean_up(&argv_value);
    aws_endpoints_eval_value_clean_up(&argv_allow_subdomains);
    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_eval_value_clean_up(&argv_value);
    aws_endpoints_eval_value_clean_up(&argv_allow_subdomains);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_eval_fn_aws_partition(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {

    struct eval_value argv_region;

    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_STRING, &argv_region)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval arguments for partitions.");
        goto on_error;
    }

    struct aws_hash_element *element = NULL;
    struct aws_byte_cursor key = argv_region.v.string.cur;
    if (aws_hash_table_find(&scope->partitions->region_to_partition_info, &key, &element)) {
        AWS_LOGF_ERROR(
            AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to find partition info. " PRInSTR, AWS_BYTE_CURSOR_PRI(key));
        goto on_error;
    }

    if (element != NULL) {
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_OBJECT;
        out_value->v.object = aws_endpoints_owning_cursor_create(
            aws_string_clone_or_reuse(allocator, ((struct aws_partition_info *)element->value)->info));
        goto on_success;
    }

    key = aws_map_region_to_partition(key);

    if (key.len == 0) {
        key = aws_byte_cursor_from_c_str("aws");
    }

    if (aws_hash_table_find(&scope->partitions->region_to_partition_info, &key, &element) || element == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to find partition info. " PRInSTR, AWS_BYTE_CURSOR_PRI(key));
        goto on_error;
    }

    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_OBJECT;
    out_value->v.object = aws_endpoints_owning_cursor_create(
        aws_string_clone_or_reuse(allocator, ((struct aws_partition_info *)element->value)->info));

on_success:
    aws_endpoints_eval_value_clean_up(&argv_region);
    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_eval_value_clean_up(&argv_region);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_eval_fn_aws_parse_arn(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {

    struct aws_json_value *object = NULL;
    struct eval_value argv_value;
    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_STRING, &argv_value)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval parseArn.");
        goto on_error;
    }

    struct aws_resource_name arn;
    if (aws_resource_name_init_from_cur(&arn, &argv_value.v.string.cur)) {
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;
        goto on_success;
    }

    object = aws_json_value_new_object(allocator);
    if (object == NULL) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to init object for parseArn.");
        goto on_error;
    }

    if (arn.partition.len == 0 || arn.resource_id.len == 0 || arn.service.len == 0) {
        out_value->type = AWS_ENDPOINTS_EVAL_VALUE_NONE;
        goto on_success;
    }

    /* Split resource id into components, either on : or / */
    /* TODO: support multiple delims in existing split helper? */
    struct aws_json_value *resource_id_node = aws_json_value_new_array(allocator);
    size_t start = 0;
    for (size_t i = 0; i < arn.resource_id.len; ++i) {
        if (arn.resource_id.ptr[i] == '/' || arn.resource_id.ptr[i] == ':') {
            struct aws_byte_cursor cur = {
                .ptr = arn.resource_id.ptr + start,
                .len = i - start,
            };

            struct aws_json_value *element = aws_json_value_new_string(allocator, cur);
            if (element == NULL || aws_json_value_add_array_element(resource_id_node, element)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to add resource id element");
                goto on_error;
            }

            start = i + 1;
        }
    }

    if (start <= arn.resource_id.len) {
        struct aws_byte_cursor cur = {
            .ptr = arn.resource_id.ptr + start,
            .len = arn.resource_id.len - start,
        };
        struct aws_json_value *element = aws_json_value_new_string(allocator, cur);
        if (element == NULL || aws_json_value_add_array_element(resource_id_node, element)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to add resource id element");
            goto on_error;
        }
    }

    if (aws_json_value_add_to_object(
            object, aws_byte_cursor_from_c_str("partition"), aws_json_value_new_string(allocator, arn.partition)) ||
        aws_json_value_add_to_object(
            object, aws_byte_cursor_from_c_str("service"), aws_json_value_new_string(allocator, arn.service)) ||
        aws_json_value_add_to_object(
            object, aws_byte_cursor_from_c_str("region"), aws_json_value_new_string(allocator, arn.region)) ||
        aws_json_value_add_to_object(
            object, aws_byte_cursor_from_c_str("accountId"), aws_json_value_new_string(allocator, arn.account_id)) ||
        aws_json_value_add_to_object(object, aws_byte_cursor_from_c_str("resourceId"), resource_id_node)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to add elements to object for parseArn.");
        goto on_error;
    }

    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_OBJECT;
    out_value->v.object = aws_endpoints_owning_cursor_create(aws_string_new_from_json(allocator, object));

    if (out_value->v.object.cur.len == 0) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to create string from json.");
        goto on_error;
    }

on_success:
    aws_json_value_destroy(object);
    aws_endpoints_eval_value_clean_up(&argv_value);
    return AWS_OP_SUCCESS;

on_error:
    aws_json_value_destroy(object);
    aws_endpoints_eval_value_clean_up(&argv_value);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

static int s_eval_is_virtual_hostable_s3_bucket(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value) {

    struct eval_value argv_value;
    struct eval_value argv_allow_subdomains;
    if (aws_endpoints_argv_expect(allocator, scope, argv, 0, AWS_ENDPOINTS_EVAL_VALUE_STRING, &argv_value) ||
        aws_endpoints_argv_expect(allocator, scope, argv, 1, AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN, &argv_allow_subdomains)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to eval args for isVirtualHostableS3Bucket.");
        goto on_error;
    }

    struct aws_byte_cursor label_cur = argv_value.v.string.cur;

    bool has_uppercase_chars = false;
    for (size_t i = 0; i < label_cur.len; ++i) {
        if (label_cur.ptr[i] >= 'A' && label_cur.ptr[i] <= 'Z') {
            has_uppercase_chars = true;
            break;
        }
    }

    out_value->type = AWS_ENDPOINTS_EVAL_VALUE_BOOLEAN;
    out_value->v.boolean = (label_cur.len >= 3 && label_cur.len <= 63) && !has_uppercase_chars &&
                           aws_is_valid_host_label(label_cur, argv_allow_subdomains.v.boolean) &&
                           !aws_is_ipv4(label_cur);

    aws_endpoints_eval_value_clean_up(&argv_value);
    aws_endpoints_eval_value_clean_up(&argv_allow_subdomains);
    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_eval_value_clean_up(&argv_value);
    aws_endpoints_eval_value_clean_up(&argv_allow_subdomains);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

typedef int(eval_function_fn)(
    struct aws_allocator *allocator,
    struct aws_array_list *argv,
    struct eval_scope *scope,
    struct eval_value *out_value);

static eval_function_fn *s_eval_fn_vt[AWS_ENDPOINTS_FN_LAST] = {
    [AWS_ENDPOINTS_FN_IS_SET] = s_eval_fn_is_set,
    [AWS_ENDPOINTS_FN_NOT] = s_eval_fn_not,
    [AWS_ENDPOINTS_FN_GET_ATTR] = s_eval_fn_get_attr,
    [AWS_ENDPOINTS_FN_SUBSTRING] = s_eval_fn_substring,
    [AWS_ENDPOINTS_FN_STRING_EQUALS] = s_eval_fn_string_equals,
    [AWS_ENDPOINTS_FN_BOOLEAN_EQUALS] = s_eval_fn_boolean_equals,
    [AWS_ENDPOINTS_FN_URI_ENCODE] = s_eval_fn_uri_encode,
    [AWS_ENDPOINTS_FN_PARSE_URL] = s_eval_fn_parse_url,
    [AWS_ENDPOINTS_FN_IS_VALID_HOST_LABEL] = s_eval_is_valid_host_label,
    [AWS_ENDPOINTS_FN_AWS_PARTITION] = s_eval_fn_aws_partition,
    [AWS_ENDPOINTS_FN_AWS_PARSE_ARN] = s_eval_fn_aws_parse_arn,
    [AWS_ENDPOINTS_FN_AWS_IS_VIRTUAL_HOSTABLE_S3_BUCKET] = s_eval_is_virtual_hostable_s3_bucket,
};

int aws_endpoints_dispatch_standard_lib_fn_resolve(enum aws_endpoints_fn_type type,
            struct aws_allocator *allocator,
            struct aws_array_list *argv,
            struct eval_scope *scope,
            struct eval_value *out_value) {
    return s_eval_fn_vt[type](allocator, argv, scope, out_value);
}
