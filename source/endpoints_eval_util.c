/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/logging.h>
#include <aws/common/string.h>
#include <aws/common/json.h>
#include <aws/sdkutils/private/endpoints_eval_util.h>
#include <aws/sdkutils/sdkutils.h>

#include <inttypes.h>

/* Disable sscanf warnings on windows. */ 
#ifdef _MSC_VER 
#    pragma warning(disable : 4204)
#    pragma warning(disable : 4706)
#    pragma warning(disable : 4996)
#endif

/* 4 octets of 3 chars max + 3 separators + null terminator */
#define AWS_IPV4_STR_LEN 16
#define IP_CHAR_FMT "%03" SCNu16

/* arbitrary max length of a region. curent longest region name is 16 chars */
#define AWS_REGION_LEN 50

bool aws_is_ipv4(struct aws_byte_cursor host) {
    if (host.len > AWS_IPV4_STR_LEN - 1) {
        return false;
    }

    char copy[AWS_IPV4_STR_LEN] = {0};
    memcpy(copy, host.ptr, host.len);

    uint16_t octet[4] = {0};
    char remainder[2] = {0};
    if (4 != sscanf(
                 copy,
                 IP_CHAR_FMT "." IP_CHAR_FMT "." IP_CHAR_FMT "." IP_CHAR_FMT "%1s",
                 &octet[0],
                 &octet[1],
                 &octet[2],
                 &octet[3],
                 remainder)) {
        return false;
    }

    for (size_t i = 0; i < 4; ++i) {
        if (octet[i] > 255) {
            return false;
        }
    }

    return true;
}

bool aws_is_ipv6(struct aws_byte_cursor host, bool is_uri_encoded) {
    if (host.len == 0) {
        return false;
    }

    if (is_uri_encoded) {
        if (host.ptr[0] != '[' || host.ptr[host.len - 1] != ']') {
            return false;
        }
        aws_byte_cursor_advance(&host, 1);
        --host.len;
    }

    /*
     * IPv6 format:
     * 8 groups of 4 hex chars separated by colons (:)
     * leading 0s in each group can be skipped
     * 2 or more consecutive zero groups can be replaced by double colon (::),
     *     but only once.
     * ipv6 literal can be scoped by to zone by appending % followed by zone name
     * ( does not look like there is length reqs on zone name length. this
     * implementation enforces that its > 1 )
     * ipv6 can be embedded in url, in which case it must be wrapped inside []
     * and % be uri encoded as %25.
     * Implementation is fairly trivial and just iterates through the string
     * keeping track of the spec above.
     */

    uint8_t *zone_delim = memchr(host.ptr, '%', host.len);

    if (zone_delim != NULL) {
        size_t zone_len = host.len - (size_t)(zone_delim - host.ptr);

        if (zone_len < (size_t)(is_uri_encoded ? 4 : 2)) {
            return false;
        }

        if (is_uri_encoded && (zone_delim[1] != '2' || zone_delim[2] != '5' || !aws_isalnum(zone_delim[3]))) {
            return false;
        }

        if (!is_uri_encoded && !aws_isalnum(zone_delim[1])) {
            return false;
        }

        host.len -= zone_len;
    }

    for (size_t i = 0; i < host.len; ++i) {
        if (!aws_isxdigit(host.ptr[i]) && host.ptr[i] != ':') {
            return false;
        }
    }

    bool has_double_colon = false;
    uint8_t colon_count = 0;

    uint8_t *colon_delim = memchr(host.ptr, ':', host.len);
    while (colon_delim != NULL) {
        size_t group_len = colon_delim - host.ptr;
        if (group_len == 0) {
            if (has_double_colon) {
                return false;
            }
            has_double_colon = true;
        } else {
            ++colon_count;
        }

        if (group_len > 4) {
            return false;
        }

        aws_byte_cursor_advance(&host, group_len + 1);
        colon_delim = memchr(host.ptr, ':', host.len);
    }

    if (host.len == 0 || host.len > 4) {
        return false;
    }

    return has_double_colon ? colon_count < 6 : colon_count == 7;
}

static char s_known_countries[][3] = {{"us"}, {"eu"}, {"ap"}, {"sa"}, {"ca"}, {"me"}, {"af"}};

struct aws_byte_cursor aws_map_region_to_partition(struct aws_byte_cursor region) {
    if (region.len > AWS_REGION_LEN - 1) {
        AWS_LOGF_ERROR(
            AWS_LS_SDKUTILS_ENDPOINTS_GENERAL,
            "Unexpected length of region string: " PRInSTR,
            AWS_BYTE_CURSOR_PRI(region));
        return aws_byte_cursor_from_c_str("");
    }

    char copy[AWS_REGION_LEN] = {0};
    memcpy(copy, region.ptr, region.len);

    char country[3] = {0};
    char location[31] = {0};
    uint8_t num = 0;

    if (3 == sscanf(copy, "%2[^-]-%30[^-]-%03" SCNu8, country, location, &num)) {
        if (location[0] != 0 && num > 0) {
            for (size_t i = 0; i < sizeof(s_known_countries) / sizeof(s_known_countries[0]); ++i) {
                if (0 == strncmp(s_known_countries[i], country, 3)) {
                    return aws_byte_cursor_from_c_str("aws");
                }
            }

            if (0 == strncmp("cn", country, 3)) {
                return aws_byte_cursor_from_c_str("aws-cn");
            }
        }
    }

    if (2 == sscanf(copy, "us-gov-%30[^-]-%03" SCNu8, location, &num)) {
        if (location[0] != 0 && num > 0) {
            return aws_byte_cursor_from_c_str("aws-us-gov");
        }
    }

    if (2 == sscanf(copy, "us-iso-%30[^-]-%03" SCNu8, location, &num)) {
        if (location[0] != 0 && num > 0) {
            return aws_byte_cursor_from_c_str("aws-iso");
        }
    }

    if (2 == sscanf(copy, "us-isob-%30[^-]-%03" SCNu8, location, &num)) {
        if (location[0] != 0 && num > 0) {
            return aws_byte_cursor_from_c_str("aws-iso-b");
        }
    }

    return aws_byte_cursor_from_c_str("");
}

bool aws_is_valid_host_label(struct aws_byte_cursor label, bool allow_subdomains) {
    bool next_must_be_alnum = true;
    size_t subdomain_count = 0;

    for (size_t i = 0; i < label.len; ++i) {
        if (label.ptr[i] == '.') {
            if (!allow_subdomains || subdomain_count == 0) {
                return false;
            }

            if (!aws_isalnum(label.ptr[i - 1])) {
                return false;
            }

            next_must_be_alnum = true;
            subdomain_count = 0;
            continue;
        }

        if (next_must_be_alnum && !aws_isalnum(label.ptr[i])) {
            return false;
        } else if (label.ptr[i] != '-' && !aws_isalnum(label.ptr[i])) {
            return false;
        }

        next_must_be_alnum = false;
        ++subdomain_count;

        if (subdomain_count > 63) {
            return false;
        }
    }

    return  (subdomain_count > 0 && subdomain_count <= 63) &&
           aws_isalnum(label.ptr[label.len - 1]);
}

static int s_replace_escaped(struct aws_allocator *allocator, struct aws_byte_cursor str, struct aws_byte_buf *out_buf) {
    uint8_t *start = str.ptr;
    size_t start_offset = 0;
    for (size_t i = 1; i < str.len; ++i) {
        if ((str.ptr[i] == '{' && str.ptr[i - 1] == '{') || (str.ptr[i] == '}' && str.ptr[i - 1] == '}')) {
            struct aws_byte_cursor prefix = {.ptr = start, .len = i - start_offset};
            if (aws_byte_buf_append_dynamic(out_buf, &prefix)) {
                AWS_LOGF_ERROR(
                    AWS_LS_SDKUTILS_ENDPOINTS_GENERAL, "Failed to append to buffer while replacing escaped.");
                goto on_error;
            }
            start_offset = ++i;
            start = str.ptr + start_offset;

            continue;
        }
    }

    if (start_offset != str.len) {
        struct aws_byte_cursor prefix = {.ptr = start, .len = str.len - start_offset};
        if (aws_byte_buf_append_dynamic(out_buf, &prefix)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_GENERAL, "Failed to append to buffer while replacing escaped.");
            goto on_error;
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

/*
 * Replaced escaped chars within endpoints templated strings.
 * Basically replaces {{ with { and }} with }.
 */
AWS_SDKUTILS_API int aws_templated_string_replace_escaped(
    struct aws_allocator *allocator,
    struct aws_byte_cursor str,
    struct aws_byte_buf *out_buf) {

    if (aws_byte_buf_init(out_buf, allocator, str.len)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_GENERAL, "Failed to init buffer during replacing escaped chars");
        goto on_error;
    }

    if (s_replace_escaped(allocator, str, out_buf)) {
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:
    aws_byte_buf_clean_up(out_buf);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

AWS_SDKUTILS_API int aws_json_templated_strings_replace_escaped(
    struct aws_allocator *allocator,
    struct aws_byte_cursor str,
    struct aws_byte_buf *out_buf) {

    if (aws_byte_buf_init(out_buf, allocator, str.len)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_GENERAL, "Failed to init buffer during replacing escaped chars");
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
    }

    uint8_t *opening = memchr(str.ptr, '"', str.len);

    while (opening != NULL) {
        struct aws_byte_cursor prefix = {.ptr = str.ptr, .len = opening - str.ptr + 1};
        if (aws_byte_buf_append_dynamic(out_buf, &prefix)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_GENERAL, "Failed to append to buffer while replacing escaped.");
            goto on_error;
        }

        aws_byte_cursor_advance(&str, prefix.len);

        uint8_t *closing = memchr(str.ptr, '"', str.len);

        if (closing != NULL) {
            struct aws_byte_cursor templated = {.ptr = str.ptr, .len = closing - opening};
            if (s_replace_escaped(allocator, templated, out_buf)) {
                goto on_error;
            }
            aws_byte_cursor_advance(&str, templated.len);
            opening = memchr(str.ptr, '"', str.len);
        } else {
            break;
        }
    }

    if (str.len > 0 && aws_byte_buf_append_dynamic(out_buf, &str)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_GENERAL, "Failed to append to buffer while replacing escaped.");
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:
    aws_byte_buf_clean_up(out_buf);
    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
}

struct aws_byte_cursor s_path_slash = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/");

int aws_uri_normalize_path(struct aws_allocator *allocator, 
                            struct aws_byte_cursor path,
                            struct aws_byte_buf *out_normalized_path) {
    /* Normalized path is just regular path that ensures that path starts and ends with slash */

    if (aws_byte_buf_init(out_normalized_path, allocator, path.len + 2)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed init buffer for parseUrl return.");
        goto on_error;
    }

    if (path.len == 0) {
        if (aws_byte_buf_append(out_normalized_path, &s_path_slash)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to add path to object.");
            goto on_error;
        }
        return AWS_OP_SUCCESS;
    }

    if (path.ptr[0] != '/') {
        if (aws_byte_buf_append_dynamic(out_normalized_path, &s_path_slash)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to append slash to normalized path.");
            goto on_error;
        }
    }

    if (aws_byte_buf_append_dynamic(out_normalized_path, &path)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to append path to normalized path.");
        goto on_error;
    }

    if (out_normalized_path->buffer[out_normalized_path->len - 1] != '/') {
        if (aws_byte_buf_append_dynamic(out_normalized_path, &s_path_slash)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to append slash to normalized path.");
            goto on_error;
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    aws_byte_buf_clean_up(out_normalized_path);
    return AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED;
}

struct aws_string *aws_string_from_json(struct aws_allocator *allocator, struct aws_json_value *value) {
    struct aws_byte_buf json_blob;
    if (aws_byte_buf_init(&json_blob, allocator, 0)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to init buffer for json conversion.");
        goto on_error;
    }

    if (aws_byte_buf_append_json_string(value, &json_blob)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_EVAL, "Failed to convert json to string.");
        goto on_error;
    }

    struct aws_string *ret = aws_string_new_from_buf(allocator, &json_blob);
    aws_byte_buf_clean_up(&json_blob);
    return ret;

on_error:
    aws_byte_buf_clean_up(&json_blob);
    aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_EVAL_FAILED);
    return NULL;
}
