/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/byte_buf.h>
#include <aws/common/encoding.h>
#include <aws/common/hash_table.h>
#include <aws/sdkutils/endpoints_bdd_engine.h>
#include <aws/sdkutils/partitions.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>
#include <aws/sdkutils/private/endpoints_util.h>

#define BDD_MAGIC_NUMBER 0x45504452 /* "EPDR" */

/* Forward declaration */
static void aws_endpoints_bdd_engine_destroy(struct aws_endpoints_bdd_engine *engine);

static void s_on_expr_array_element_clean_up(void *element) {
    struct aws_endpoints_expr *expr = element;
    aws_endpoints_expr_clean_up(expr);
}

static void s_on_kv_pair_array_element_clean_up(void *element) {
    struct aws_endpoints_kv_pair *pair = element;
    if (pair->value) {
        aws_endpoints_expr_clean_up(pair->value);
        aws_mem_release(pair->allocator, pair->value);
    }
}

static void s_on_condition_array_element_clean_up(void *element) {
    struct aws_endpoints_condition *condition = element;
    aws_endpoints_condition_clean_up(condition);
}

static int s_read_u16(struct aws_byte_cursor *cursor, uint16_t *out) {
    if (cursor->len < 2) {
        return AWS_OP_ERR;
    }
    *out = (uint16_t)cursor->ptr[0] | ((uint16_t)cursor->ptr[1] << 8);
    aws_byte_cursor_advance(cursor, 2);
    return AWS_OP_SUCCESS;
}

static int s_read_u32(struct aws_byte_cursor *cursor, uint32_t *out) {
    if (cursor->len < 4) {
        return AWS_OP_ERR;
    }
    *out = (uint32_t)cursor->ptr[0] | ((uint32_t)cursor->ptr[1] << 8) | ((uint32_t)cursor->ptr[2] << 16) |
           ((uint32_t)cursor->ptr[3] << 24);
    aws_byte_cursor_advance(cursor, 4);
    return AWS_OP_SUCCESS;
}

static int s_read_i32(struct aws_byte_cursor *cursor, int32_t *out) {
    uint32_t val;
    if (s_read_u32(cursor, &val)) {
        return AWS_OP_ERR;
    }
    *out = (int32_t)val;
    return AWS_OP_SUCCESS;
}

static int s_validate_magic_number(struct aws_byte_cursor *cursor) {
    uint32_t magic;
    if (s_read_u32(cursor, &magic)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (magic != BDD_MAGIC_NUMBER) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    return AWS_OP_SUCCESS;
}

static int s_load_string_table(
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor *out_blob) {

    uint32_t blob_size;
    if (s_read_u32(cursor, &blob_size)) {
        return AWS_OP_ERR;
    }

    if (cursor->len < blob_size) {
        return AWS_OP_ERR;
    }

    *out_blob = aws_byte_cursor_from_array(cursor->ptr, blob_size);
    aws_byte_cursor_advance(cursor, blob_size);
    return AWS_OP_SUCCESS;
}

static int s_read_string_ref(
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_byte_cursor *out) {

    uint16_t offset, length;
    if (s_read_u16(cursor, &offset) || s_read_u16(cursor, &length)) {
        return AWS_OP_ERR;
    }
    if ((size_t)offset + length > blob.len) {
        return AWS_OP_ERR;
    }
    *out = aws_byte_cursor_from_array(blob.ptr + offset, length);
    return AWS_OP_SUCCESS;
}

static void s_callback_endpoints_parameter_destroy(void *data) {
    struct aws_endpoints_parameter *parameter = data;
    aws_endpoints_parameter_destroy(parameter);
}

static int s_load_parameters(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_hash_table *out_parameters) {

    uint16_t count;
    if (s_read_u16(cursor, &count)) {
        return AWS_OP_ERR;
    }

    if (aws_hash_table_init(
            out_parameters,
            allocator,
            count,
            aws_hash_byte_cursor_ptr,
            aws_endpoints_byte_cursor_eq,
            NULL,
            s_callback_endpoints_parameter_destroy)) {
        return AWS_OP_ERR;
    }

    for (uint16_t i = 0; i < count; ++i) {
        uint8_t opcode;
        if (cursor->len < 1) {
            goto error;
        }
        opcode = cursor->ptr[0];
        aws_byte_cursor_advance(cursor, 1);

        if (opcode != 0x01 && opcode != 0x02) {
            goto error;
        }

        struct aws_endpoints_parameter *param = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_parameter));
        if (!param) {
            goto error;
        }
        param->allocator = allocator;
        param->type = (opcode == 0x01) ? AWS_ENDPOINTS_PARAMETER_STRING : AWS_ENDPOINTS_PARAMETER_BOOLEAN;

        if (s_read_string_ref(cursor, blob, &param->name)) {
            aws_mem_release(allocator, param);
            goto error;
        }

        uint8_t has_default;
        if (cursor->len < 1) {
            aws_mem_release(allocator, param);
            goto error;
        }
        has_default = cursor->ptr[0];
        aws_byte_cursor_advance(cursor, 1);
        param->has_default_value = (has_default != 0);

        if (has_default) {
            if (param->type == AWS_ENDPOINTS_PARAMETER_STRING) {
                struct aws_byte_cursor default_cur;
                if (s_read_string_ref(cursor, blob, &default_cur)) {
                    aws_mem_release(allocator, param);
                    goto error;
                }
                param->default_value.type = AWS_ENDPOINTS_VALUE_STRING;
                param->default_value.v.owning_cursor_string.cur = default_cur;
                param->default_value.is_ref = true;
            } else {
                if (cursor->len < 1) {
                    aws_mem_release(allocator, param);
                    goto error;
                }
                uint8_t bool_val = cursor->ptr[0];
                aws_byte_cursor_advance(cursor, 1);
                param->default_value.type = AWS_ENDPOINTS_VALUE_BOOLEAN;
                param->default_value.v.boolean = (bool_val != 0);
            }
        }

        /* Read required flag */
        if (cursor->len < 1) {
            aws_mem_release(allocator, param);
            goto error;
        }
        param->is_required = (cursor->ptr[0] != 0);
        aws_byte_cursor_advance(cursor, 1);

        /* Read has_builtin flag + optional builtin string ref */
        if (cursor->len < 1) {
            aws_mem_release(allocator, param);
            goto error;
        }
        uint8_t has_builtin = cursor->ptr[0];
        aws_byte_cursor_advance(cursor, 1);
        if (has_builtin) {
            if (s_read_string_ref(cursor, blob, &param->built_in)) {
                aws_mem_release(allocator, param);
                goto error;
            }
        }

        if (aws_hash_table_put(out_parameters, &param->name, param, NULL)) {
            aws_mem_release(allocator, param);
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

error:
    aws_hash_table_clean_up(out_parameters);
    return AWS_OP_ERR;
}

/* Forward declaration for recursive value decoding */
static int s_decode_value(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_endpoints_expr *out_expr);

static int s_decode_value(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_endpoints_expr *out_expr) {

    if (cursor->len < 1) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "No bytes left to read value tag");
        return AWS_OP_ERR;
    }

    uint8_t tag = cursor->ptr[0];
    aws_byte_cursor_advance(cursor, 1);
    AWS_LOGF_DEBUG(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Decoding value with tag: %d", (int)tag);

    switch (tag) {
        case 0: /* None - represented as empty string */
            out_expr->type = AWS_ENDPOINTS_EXPR_STRING;
            out_expr->e.string = aws_byte_cursor_from_c_str("");
            break;

        case 1: { /* String */
            struct aws_byte_cursor str_cur;
            if (s_read_string_ref(cursor, blob, &str_cur)) {
                return AWS_OP_ERR;
            }
            out_expr->type = AWS_ENDPOINTS_EXPR_STRING;
            out_expr->e.string = str_cur;
            break;
        }

        case 2: { /* Boolean */
            if (cursor->len < 1) {
                return AWS_OP_ERR;
            }
            uint8_t bool_val = cursor->ptr[0];
            aws_byte_cursor_advance(cursor, 1);
            out_expr->type = AWS_ENDPOINTS_EXPR_BOOLEAN;
            out_expr->e.boolean = (bool_val != 0);
            break;
        }

        case 3: { /* Integer */
            int32_t int_val;
            if (s_read_i32(cursor, &int_val)) {
                return AWS_OP_ERR;
            }
            out_expr->type = AWS_ENDPOINTS_EXPR_NUMBER;
            out_expr->e.number = (double)int_val;
            break;
        }

        case 4: { /* Reference */
            struct aws_byte_cursor ref_cur;
            if (s_read_string_ref(cursor, blob, &ref_cur)) {
                return AWS_OP_ERR;
            }
            out_expr->type = AWS_ENDPOINTS_EXPR_REFERENCE;
            out_expr->e.reference = ref_cur;
            break;
        }

        case 5: { /* Function */
            struct aws_byte_cursor fn_name;
            if (s_read_string_ref(cursor, blob, &fn_name)) {
                return AWS_OP_ERR;
            }

            uint16_t argc;
            if (s_read_u16(cursor, &argc)) {
                return AWS_OP_ERR;
            }

            out_expr->type = AWS_ENDPOINTS_EXPR_FUNCTION;
            out_expr->e.function.fn = AWS_ENDPOINTS_FN_LAST;

            /* Resolve function name to enum */
            uint64_t hash = aws_hash_byte_cursor_ptr(&fn_name);
            for (int idx = AWS_ENDPOINTS_FN_FIRST; idx < AWS_ENDPOINTS_FN_LAST; ++idx) {
                if (aws_endpoints_fn_name_hash[idx] == hash) {
                    out_expr->e.function.fn = idx;
                    break;
                }
            }

            /* Note: fn may remain AWS_ENDPOINTS_FN_LAST for new BDD functions (ite, coalesce, split) */

            if (aws_array_list_init_dynamic(
                    &out_expr->e.function.argv, allocator, argc, sizeof(struct aws_endpoints_expr))) {
                return AWS_OP_ERR;
            }

            for (uint16_t i = 0; i < argc; ++i) {
                struct aws_endpoints_expr arg;
                if (s_decode_value(allocator, cursor, blob, &arg)) {
                    aws_array_list_deep_clean_up(&out_expr->e.function.argv, s_on_expr_array_element_clean_up);
                    return AWS_OP_ERR;
                }
                if (aws_array_list_push_back(&out_expr->e.function.argv, &arg)) {
                    aws_endpoints_expr_clean_up(&arg);
                    aws_array_list_deep_clean_up(&out_expr->e.function.argv, s_on_expr_array_element_clean_up);
                    return AWS_OP_ERR;
                }
            }
            break;
        }

        case 6: { /* Array */
            uint16_t length;
            if (s_read_u16(cursor, &length)) {
                return AWS_OP_ERR;
            }

            out_expr->type = AWS_ENDPOINTS_EXPR_ARRAY;
            if (aws_array_list_init_dynamic(&out_expr->e.array, allocator, length, sizeof(struct aws_endpoints_expr))) {
                return AWS_OP_ERR;
            }

            for (uint16_t i = 0; i < length; ++i) {
                struct aws_endpoints_expr elem;
                if (s_decode_value(allocator, cursor, blob, &elem)) {
                    aws_array_list_deep_clean_up(&out_expr->e.array, s_on_expr_array_element_clean_up);
                    return AWS_OP_ERR;
                }
                if (aws_array_list_push_back(&out_expr->e.array, &elem)) {
                    aws_endpoints_expr_clean_up(&elem);
                    aws_array_list_deep_clean_up(&out_expr->e.array, s_on_expr_array_element_clean_up);
                    return AWS_OP_ERR;
                }
            }
            break;
        }

        case 7: { /* Object */
            uint16_t length;
            if (s_read_u16(cursor, &length)) {
                return AWS_OP_ERR;
            }

            out_expr->type = AWS_ENDPOINTS_EXPR_OBJECT;
            if (aws_array_list_init_dynamic(
                    &out_expr->e.object, allocator, length, sizeof(struct aws_endpoints_kv_pair))) {
                return AWS_OP_ERR;
            }

            for (uint16_t i = 0; i < length; ++i) {
                struct aws_byte_cursor key_cur;
                if (s_read_string_ref(cursor, blob, &key_cur)) {
                    aws_array_list_deep_clean_up(&out_expr->e.object, s_on_kv_pair_array_element_clean_up);
                    return AWS_OP_ERR;
                }

                struct aws_endpoints_kv_pair pair;
                pair.allocator = allocator;
                pair.key = key_cur;
                pair.value = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_expr));
                if (!pair.value) {
                    aws_array_list_deep_clean_up(&out_expr->e.object, s_on_kv_pair_array_element_clean_up);
                    return AWS_OP_ERR;
                }

                if (s_decode_value(allocator, cursor, blob, pair.value)) {
                    aws_endpoints_expr_clean_up(pair.value);
                    aws_mem_release(allocator, pair.value);
                    aws_array_list_deep_clean_up(&out_expr->e.object, s_on_kv_pair_array_element_clean_up);
                    return AWS_OP_ERR;
                }

                if (aws_array_list_push_back(&out_expr->e.object, &pair)) {
                    aws_endpoints_expr_clean_up(pair.value);
                    aws_mem_release(allocator, pair.value);
                    aws_array_list_deep_clean_up(&out_expr->e.object, s_on_kv_pair_array_element_clean_up);
                    return AWS_OP_ERR;
                }
            }
            break;
        }

        default:
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Unknown value tag: %d", (int)tag);
            return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_load_conditions(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_array_list *out_conditions) {

    uint16_t count;
    if (s_read_u16(cursor, &count)) {
        return AWS_OP_ERR;
    }

    if (aws_array_list_init_dynamic(out_conditions, allocator, count, sizeof(struct aws_endpoints_condition))) {
        return AWS_OP_ERR;
    }

    for (uint16_t i = 0; i < count; ++i) {
        uint8_t opcode;
        if (cursor->len < 1) {
            goto error;
        }
        opcode = cursor->ptr[0];
        aws_byte_cursor_advance(cursor, 1);

        if (opcode != 0x10) {
            goto error;
        }

        struct aws_endpoints_condition cond;
        AWS_ZERO_STRUCT(cond);

        struct aws_byte_cursor fn_name;
        if (s_read_string_ref(cursor, blob, &fn_name)) {
            goto error;
        }

        uint16_t argc;
        if (s_read_u16(cursor, &argc)) {
            goto error;
        }

        /* Construct FUNCTION expression from fn_name and argc */
        cond.expr.type = AWS_ENDPOINTS_EXPR_FUNCTION;
        cond.expr.e.function.fn = AWS_ENDPOINTS_FN_LAST;

        /* Resolve function name to enum */
        uint64_t hash = aws_hash_byte_cursor_ptr(&fn_name);
        for (int idx = AWS_ENDPOINTS_FN_FIRST; idx < AWS_ENDPOINTS_FN_LAST; ++idx) {
            if (aws_endpoints_fn_name_hash[idx] == hash) {
                cond.expr.e.function.fn = idx;
                break;
            }
        }

        /* Note: fn may remain AWS_ENDPOINTS_FN_LAST for new BDD functions (ite, coalesce, split) */

        if (aws_array_list_init_dynamic(
                &cond.expr.e.function.argv, allocator, argc, sizeof(struct aws_endpoints_expr))) {
            goto error;
        }

        for (uint16_t arg_i = 0; arg_i < argc; ++arg_i) {
            struct aws_endpoints_expr arg;
            if (s_decode_value(allocator, cursor, blob, &arg)) {
                aws_array_list_deep_clean_up(&cond.expr.e.function.argv, s_on_expr_array_element_clean_up);
                goto error;
            }
            if (aws_array_list_push_back(&cond.expr.e.function.argv, &arg)) {
                aws_endpoints_expr_clean_up(&arg);
                aws_array_list_deep_clean_up(&cond.expr.e.function.argv, s_on_expr_array_element_clean_up);
                goto error;
            }
        }

        uint8_t has_assign;
        if (cursor->len < 1) {
            aws_endpoints_expr_clean_up(&cond.expr);
            goto error;
        }
        has_assign = cursor->ptr[0];
        aws_byte_cursor_advance(cursor, 1);

        if (has_assign) {
            struct aws_byte_cursor assign_cur;
            if (s_read_string_ref(cursor, blob, &assign_cur)) {
                aws_endpoints_expr_clean_up(&cond.expr);
                goto error;
            }
            cond.assign = assign_cur;
        }

        if (aws_array_list_push_back(out_conditions, &cond)) {
            aws_endpoints_expr_clean_up(&cond.expr);
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

error:
    for (size_t i = 0; i < aws_array_list_length(out_conditions); ++i) {
        struct aws_endpoints_condition *c = NULL;
        aws_array_list_get_at_ptr(out_conditions, (void **)&c, i);
        if (c) {
            aws_endpoints_expr_clean_up(&c->expr);
        }
    }
    aws_array_list_clean_up(out_conditions);
    return AWS_OP_ERR;
}

static int s_append_json_escaped_string(struct aws_byte_buf *buf, const struct aws_byte_cursor *str) {
    if (aws_byte_buf_append_byte_dynamic(buf, '"')) {
        return AWS_OP_ERR;
    }
    for (size_t i = 0; i < str->len; i++) {
        uint8_t c = str->ptr[i];
        if (c == '"' || c == '\\') {
            if (aws_byte_buf_append_byte_dynamic(buf, '\\') || aws_byte_buf_append_byte_dynamic(buf, c)) {
                return AWS_OP_ERR;
            }
        } else if (c < 0x20) {
            char escape[7];
            snprintf(escape, sizeof(escape), "\\u%04x", c);
            struct aws_byte_cursor esc_cur = aws_byte_cursor_from_c_str(escape);
            if (aws_byte_buf_append_dynamic(buf, &esc_cur)) {
                return AWS_OP_ERR;
            }
        } else {
            if (aws_byte_buf_append_byte_dynamic(buf, c)) {
                return AWS_OP_ERR;
            }
        }
    }
    return aws_byte_buf_append_byte_dynamic(buf, '"');
}

static int s_serialize_value_to_json(struct aws_byte_buf *buf, const struct aws_endpoints_expr *value) {
    switch (value->type) {
        case AWS_ENDPOINTS_EXPR_STRING:
            return s_append_json_escaped_string(buf, &value->e.string);
        case AWS_ENDPOINTS_EXPR_BOOLEAN: {
            struct aws_byte_cursor bool_str =
                value->e.boolean ? aws_byte_cursor_from_c_str("true") : aws_byte_cursor_from_c_str("false");
            return aws_byte_buf_append_dynamic(buf, &bool_str);
        }
        case AWS_ENDPOINTS_EXPR_NUMBER: {
            char num_buf[32];
            int written = snprintf(num_buf, sizeof(num_buf), "%g", value->e.number);
            if (written < 0 || written >= sizeof(num_buf)) {
                return AWS_OP_ERR;
            }
            struct aws_byte_cursor num_cursor = aws_byte_cursor_from_array(num_buf, written);
            return aws_byte_buf_append_dynamic(buf, &num_cursor);
        }
        case AWS_ENDPOINTS_EXPR_ARRAY: {
            if (aws_byte_buf_append_byte_dynamic(buf, '[')) {
                return AWS_OP_ERR;
            }
            size_t len = aws_array_list_length(&value->e.array);
            for (size_t i = 0; i < len; ++i) {
                struct aws_endpoints_expr *elem = NULL;
                aws_array_list_get_at_ptr(&value->e.array, (void **)&elem, i);
                if (i > 0 && aws_byte_buf_append_byte_dynamic(buf, ',')) {
                    return AWS_OP_ERR;
                }
                if (s_serialize_value_to_json(buf, elem)) {
                    return AWS_OP_ERR;
                }
            }
            return aws_byte_buf_append_byte_dynamic(buf, ']');
        }
        case AWS_ENDPOINTS_EXPR_OBJECT: {
            if (aws_byte_buf_append_byte_dynamic(buf, '{')) {
                return AWS_OP_ERR;
            }
            size_t len = aws_array_list_length(&value->e.object);
            for (size_t i = 0; i < len; ++i) {
                struct aws_endpoints_kv_pair *pair = NULL;
                aws_array_list_get_at_ptr(&value->e.object, (void **)&pair, i);
                if (i > 0 && aws_byte_buf_append_byte_dynamic(buf, ',')) {
                    return AWS_OP_ERR;
                }
                if (s_append_json_escaped_string(buf, &pair->key)) {
                    return AWS_OP_ERR;
                }
                if (aws_byte_buf_append_byte_dynamic(buf, ':')) {
                    return AWS_OP_ERR;
                }
                if (s_serialize_value_to_json(buf, pair->value)) {
                    return AWS_OP_ERR;
                }
            }
            return aws_byte_buf_append_byte_dynamic(buf, '}');
        }
        default:
            return AWS_OP_ERR;
    }
}

static int s_load_results(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_array_list *out_results) {

    uint16_t count;
    if (s_read_u16(cursor, &count)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to read result count");
        return AWS_OP_ERR;
    }
    AWS_LOGF_DEBUG(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Loading %d results", (int)count);

    if (aws_array_list_init_dynamic(out_results, allocator, count + 1, sizeof(struct aws_endpoints_bdd_result))) {
        return AWS_OP_ERR;
    }

    /* Insert NoMatchRule as results[0] */
    struct aws_endpoints_bdd_result no_match;
    AWS_ZERO_STRUCT(no_match);
    no_match.type = AWS_ENDPOINTS_RESOLVED_ERROR;
    no_match.data.error.error = aws_byte_cursor_from_c_str("No matching rule");
    if (aws_array_list_push_back(out_results, &no_match)) {
        goto error;
    }

    for (uint16_t i = 0; i < count; ++i) {
        uint8_t opcode;
        if (cursor->len < 1) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to read opcode for result %d", (int)i);
            goto error;
        }
        opcode = cursor->ptr[0];
        aws_byte_cursor_advance(cursor, 1);
        AWS_LOGF_DEBUG(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Result %d opcode: 0x%02x", (int)i, opcode);

        struct aws_endpoints_bdd_result result;
        AWS_ZERO_STRUCT(result);

        if (opcode == 0x20) { /* Endpoint */
            result.type = AWS_ENDPOINTS_RESOLVED_ENDPOINT;

            struct aws_byte_cursor url_cur;
            if (s_read_string_ref(cursor, blob, &url_cur)) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to read URL for result %d", (int)i);
                goto error;
            }
            result.data.endpoint.url = url_cur;

            uint16_t property_count;
            if (s_read_u16(cursor, &property_count)) {
                AWS_LOGF_ERROR(
                    AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to read property count for result %d", (int)i);
                goto error;
            }
            AWS_LOGF_DEBUG(
                AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Result %d has %d properties", (int)i, (int)property_count);

            if (aws_byte_buf_init(&result.data.endpoint.properties, allocator, 256)) {
                goto error;
            }

            /* Encode properties as JSON object */
            struct aws_byte_cursor open_brace = aws_byte_cursor_from_c_str("{");
            if (aws_byte_buf_append_dynamic(&result.data.endpoint.properties, &open_brace)) {
                aws_byte_buf_clean_up(&result.data.endpoint.properties);
                goto error;
            }

            for (uint16_t j = 0; j < property_count; ++j) {
                struct aws_byte_cursor key_cur;
                if (s_read_string_ref(cursor, blob, &key_cur)) {
                    AWS_LOGF_ERROR(
                        AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE,
                        "Failed to read key for property %d of result %d",
                        (int)j,
                        (int)i);
                    aws_byte_buf_clean_up(&result.data.endpoint.properties);
                    goto error;
                }

                /* Decode value */
                struct aws_endpoints_expr value_expr;
                if (s_decode_value(allocator, cursor, blob, &value_expr)) {
                    AWS_LOGF_ERROR(
                        AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE,
                        "Failed to decode value for property %d of result %d",
                        (int)j,
                        (int)i);
                    aws_byte_buf_clean_up(&result.data.endpoint.properties);
                    goto error;
                }

                /* Add comma separator if not first property */
                if (j > 0) {
                    struct aws_byte_cursor comma = aws_byte_cursor_from_c_str(",");
                    if (aws_byte_buf_append_dynamic(&result.data.endpoint.properties, &comma)) {
                        aws_endpoints_expr_clean_up(&value_expr);
                        aws_byte_buf_clean_up(&result.data.endpoint.properties);
                        goto error;
                    }
                }

                /* Add key with JSON escaping */
                if (s_append_json_escaped_string(&result.data.endpoint.properties, &key_cur)) {
                    aws_endpoints_expr_clean_up(&value_expr);
                    aws_byte_buf_clean_up(&result.data.endpoint.properties);
                    goto error;
                }
                struct aws_byte_cursor colon = aws_byte_cursor_from_c_str(":");
                if (aws_byte_buf_append_dynamic(&result.data.endpoint.properties, &colon)) {
                    aws_endpoints_expr_clean_up(&value_expr);
                    aws_byte_buf_clean_up(&result.data.endpoint.properties);
                    goto error;
                }

                /* Add value with proper serialization */
                if (s_serialize_value_to_json(&result.data.endpoint.properties, &value_expr)) {
                    aws_endpoints_expr_clean_up(&value_expr);
                    aws_byte_buf_clean_up(&result.data.endpoint.properties);
                    goto error;
                }

                aws_endpoints_expr_clean_up(&value_expr);
            }

            struct aws_byte_cursor close_brace = aws_byte_cursor_from_c_str("}");
            if (aws_byte_buf_append_dynamic(&result.data.endpoint.properties, &close_brace)) {
                aws_byte_buf_clean_up(&result.data.endpoint.properties);
                goto error;
            }

        } else if (opcode == 0x21) { /* Error */
            result.type = AWS_ENDPOINTS_RESOLVED_ERROR;

            struct aws_byte_cursor error_cur;
            if (s_read_string_ref(cursor, blob, &error_cur)) {
                goto error;
            }
            result.data.error.error = error_cur;

        } else {
            goto error;
        }

        if (aws_array_list_push_back(out_results, &result)) {
            if (result.type == AWS_ENDPOINTS_RESOLVED_ENDPOINT) {
                aws_byte_buf_clean_up(&result.data.endpoint.properties);
            }
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

error:
    for (size_t i = 0; i < aws_array_list_length(out_results); ++i) {
        struct aws_endpoints_bdd_result *r = NULL;
        aws_array_list_get_at_ptr(out_results, (void **)&r, i);
        if (r && r->type == AWS_ENDPOINTS_RESOLVED_ENDPOINT) {
            aws_byte_buf_clean_up(&r->data.endpoint.properties);
        }
    }
    aws_array_list_clean_up(out_results);
    return AWS_OP_ERR;
}

static int s_load_nodes(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cursor,
    int32_t *out_root_ref,
    uint32_t *out_node_count,
    struct aws_endpoints_bdd_node **out_nodes) {

    /* Read root reference */
    if (s_read_i32(cursor, out_root_ref)) {
        return AWS_OP_ERR;
    }

    /* Read node count */
    if (s_read_u32(cursor, out_node_count)) {
        return AWS_OP_ERR;
    }

    /* Read base64 blob length */
    uint16_t base64_length;
    if (s_read_u16(cursor, &base64_length)) {
        return AWS_OP_ERR;
    }

    if (cursor->len < base64_length) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor base64_data = aws_byte_cursor_advance(cursor, base64_length);

    /* Compute decoded size */
    size_t decoded_size = 0;
    if (aws_base64_compute_decoded_len(&base64_data, &decoded_size)) {
        return AWS_OP_ERR;
    }

    /* Allocate buffer for decoded data */
    struct aws_byte_buf decoded_buf;
    if (aws_byte_buf_init(&decoded_buf, allocator, decoded_size)) {
        return AWS_OP_ERR;
    }

    /* Decode base64 */
    if (aws_base64_decode(&base64_data, &decoded_buf)) {
        aws_byte_buf_clean_up(&decoded_buf);
        return AWS_OP_ERR;
    }

    /* Validate decoded size matches expected node count */
    size_t expected_size = *out_node_count * 12; /* 3 int32s per node */
    if (decoded_buf.len != expected_size) {
        aws_byte_buf_clean_up(&decoded_buf);
        return AWS_OP_ERR;
    }

    /* Allocate node array */
    struct aws_endpoints_bdd_node *nodes =
        aws_mem_calloc(allocator, *out_node_count, sizeof(struct aws_endpoints_bdd_node));
    if (!nodes) {
        aws_byte_buf_clean_up(&decoded_buf);
        return AWS_OP_ERR;
    }

    /* Parse nodes from decoded buffer */
    struct aws_byte_cursor node_cursor = aws_byte_cursor_from_buf(&decoded_buf);
    for (uint32_t i = 0; i < *out_node_count; ++i) {
        if (s_read_i32(&node_cursor, &nodes[i].condition_index)) {
            aws_mem_release(allocator, nodes);
            aws_byte_buf_clean_up(&decoded_buf);
            return AWS_OP_ERR;
        }
        if (s_read_i32(&node_cursor, &nodes[i].high_ref)) {
            aws_mem_release(allocator, nodes);
            aws_byte_buf_clean_up(&decoded_buf);
            return AWS_OP_ERR;
        }
        if (s_read_i32(&node_cursor, &nodes[i].low_ref)) {
            aws_mem_release(allocator, nodes);
            aws_byte_buf_clean_up(&decoded_buf);
            return AWS_OP_ERR;
        }
    }

    aws_byte_buf_clean_up(&decoded_buf);
    *out_nodes = nodes;
    return AWS_OP_SUCCESS;
}

struct aws_endpoints_bdd_engine *aws_endpoints_bdd_engine_new_from_bytecode(
    struct aws_allocator *allocator,
    struct aws_byte_cursor bytecode,
    struct aws_partitions_config *partitions_config) {

    struct aws_endpoints_bdd_engine *engine = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_bdd_engine));
    if (!engine) {
        return NULL;
    }

    engine->allocator = allocator;
    aws_ref_count_init(&engine->ref_count, engine, (aws_simple_completion_callback *)aws_endpoints_bdd_engine_destroy);
    engine->partitions_config = aws_partitions_config_acquire(partitions_config);

    /* Validate magic number */
    if (s_validate_magic_number(&bytecode)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to validate magic number");
        goto error;
    }

    /* Load string table */
    if (s_load_string_table(&bytecode, &engine->string_blob)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to load string table");
        goto error;
    }

    /* Read version */
    struct aws_byte_cursor version_cur;
    if (s_read_string_ref(&bytecode, engine->string_blob, &version_cur)) {
        goto error;
    }
    engine->version = version_cur;

    /* Load parameters */
    if (s_load_parameters(allocator, &bytecode, engine->string_blob, &engine->parameters)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to load parameters");
        goto error;
    }
    AWS_LOGF_DEBUG(
        AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE,
        "Loaded %d parameters",
        (int)aws_hash_table_get_entry_count(&engine->parameters));

    /* Load conditions */
    if (s_load_conditions(allocator, &bytecode, engine->string_blob, &engine->conditions)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to load conditions");
        goto error;
    }
    AWS_LOGF_DEBUG(
        AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Loaded %d conditions", (int)aws_array_list_length(&engine->conditions));

    /* Load results */
    if (s_load_results(allocator, &bytecode, engine->string_blob, &engine->results)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to load results");
        goto error;
    }
    AWS_LOGF_DEBUG(
        AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Loaded %d results", (int)aws_array_list_length(&engine->results));

    /* Load nodes */
    if (s_load_nodes(allocator, &bytecode, &engine->root_ref, &engine->node_count, &engine->nodes)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to load nodes");
        goto error;
    }
    AWS_LOGF_DEBUG(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Loaded %d nodes", (int)engine->node_count);

    return engine;

error:
    aws_endpoints_bdd_engine_destroy(engine);
    return NULL;
}

static void aws_endpoints_bdd_engine_destroy(struct aws_endpoints_bdd_engine *engine) {
    if (!engine) {
        return;
    }

    if (engine->partitions_config) {
        aws_partitions_config_release(engine->partitions_config);
    }

    aws_hash_table_clean_up(&engine->parameters);
    aws_array_list_deep_clean_up(&engine->conditions, s_on_condition_array_element_clean_up);

    for (size_t i = 0; i < aws_array_list_length(&engine->results); ++i) {
        struct aws_endpoints_bdd_result *r = NULL;
        aws_array_list_get_at_ptr(&engine->results, (void **)&r, i);
        if (r && r->type == AWS_ENDPOINTS_RESOLVED_ENDPOINT) {
            aws_byte_buf_clean_up(&r->data.endpoint.properties);
        }
    }
    aws_array_list_clean_up(&engine->results);

    if (engine->nodes) {
        aws_mem_release(engine->allocator, engine->nodes);
    }

    aws_mem_release(engine->allocator, engine);
}

struct aws_endpoints_bdd_engine *aws_endpoints_bdd_engine_acquire(struct aws_endpoints_bdd_engine *engine) {
    if (engine) {
        aws_ref_count_acquire(&engine->ref_count);
    }
    return engine;
}

struct aws_endpoints_bdd_engine *aws_endpoints_bdd_engine_release(struct aws_endpoints_bdd_engine *engine) {
    if (engine) {
        aws_ref_count_release(&engine->ref_count);
    }
    return NULL;
}
