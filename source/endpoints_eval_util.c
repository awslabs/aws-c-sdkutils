/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/string.h>
#include <aws/sdkutils/private/endpoints_eval_util.h>
#include <aws/sdkutils/sdkutils.h>

#include <inttypes.h>

#define IP_CHAR_FMT "%03" SCNu16

struct aws_byte_cursor aws_byte_cursor_from_substring(const struct aws_string *src, size_t start, size_t end) {
    AWS_PRECONDITION(aws_string_is_valid(src));
    AWS_PRECONDITION(start < end && end <= src->len);

    return aws_byte_cursor_from_array(aws_string_bytes(src) + start, end - start);
}

bool aws_is_ipv4(struct aws_allocator *allocator, struct aws_byte_cursor host) {
    struct aws_string *host_str = aws_string_new_from_cursor(allocator, &host);
    
    bool is_ip = false;
    uint16_t octet[4] = {0};
    char remainder[2] = {0};
    if (4 != sscanf(aws_string_c_str(host_str),
        IP_CHAR_FMT "." IP_CHAR_FMT "." IP_CHAR_FMT "." IP_CHAR_FMT "%1s",
            &octet[0], &octet[1], &octet[2], &octet[3], remainder)) {
        goto on_exit;
    }

    for (size_t i = 0; i < 4; ++i) {
        if (octet[i] > 255) {
            goto on_exit;
        }
    }

    is_ip = true;

on_exit:
    aws_string_destroy(host_str);
    return is_ip;
}

bool aws_is_ipv6(struct aws_allocator *allocator, struct aws_byte_cursor host, bool is_uri_encoded) {
    
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
    bool in_zone_section = false;
    bool has_double_colon = false;
    uint8_t colon_count = 0;
    uint8_t last_group_count = 0;

    for (size_t i = 0; i < host.len; ++i) {
        if (last_group_count > 4 || colon_count > 7) {
            return false;
        }

        if (host.ptr[i] == ':') {
            if (i + 1 == host.len) { /* cant end with : */
                return false; 
            }

            last_group_count = 0;
            if (host.ptr[i+1] == ':') {
                if (i + 2 == host.len) { /* cant end with :: */
                    return false; 
                }
                has_double_colon = true;
                ++i;
                continue;
            }
            ++colon_count;
            continue;
        }

        if (host.ptr[i] == '%') {
            /* must have enough space for uri encoding if specified and zone */
            /* TODO: can probably enforce zone being moe than 1 */
            if (i + (is_uri_encoded ? 3 : 1) >= host.len) {
                return false; 
            }

            if (is_uri_encoded) {
                if (host.ptr[i+1] != '2' || host.ptr[i+2] != '5') {
                    return false; 
                }
                i += 2;
            }

            in_zone_section = true;
            continue;
        }

        if (!(in_zone_section ? aws_isalnum(host.ptr[i]) : aws_isxdigit(host.ptr[i]))) {
            return false;
        }

        ++last_group_count;
    }

    return last_group_count <= 4 && 
        /* double colon can only be used to encode 2 or more 0 groups, hence at
            most there will be five colons */
        has_double_colon ? colon_count < 6 : colon_count == 7;
}
