/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/sdkutils/private/endpoints_regex.h>

/*
 * Minimal regex implementation.
 * Inspired by
 * https://www.cs.princeton.edu/courses/archive/spr09/cos333/beautiful.html and
 * https://github.com/kokke/tiny-regex-c.
 *
 * Why write our own regex implementation?
 * Unfortunately, state of cross-platform regex support for c is rather limited.
 * Posix has regex support, but implementation support varies cross platform.
 * Windows supports regex, but only exposes it through C++ interface.
 * For 3p implementations tiny-regex-c comes closest to what we need, but has
 * several deal-breaking limitations, ex. not being thread safe, lack of
 * alternations support.
 * Other 3p C implementations are very bloated for what we need.
 * Hence, since we need a very minimal regex support for endpoint resolution we
 * just implement our own.
 *
 * What is supported?
 * - multithread safe iterative matching (stack friendly, since this is
 *   typically called deep in call stack)
 * - char matching (plain chars, alpha/digit wildcards)
 * - star and plus (refer to limitations sections for limitations on how they work)
 * - alternation groups
 *
 * Limitations?
 * - star and plus are greedy (match as much as they can), but do not backtrace.
 *   This is major deviation from how regex matching should work.
 *   Note: regions in aws have a predefined pattern where sections are separated
 *   by '-', so current implementation just matches until it hits separator.
 * - grouping using ( and ) is only supported for alternations.
 * - regex must match the whole text, i.e. start with ^ and end with $
 * - features not called out above are not supported
 */

enum regex_symbol_type {
    AWS_ENDPOINTS_REGEX_SYMBOL_DOT,
    AWS_ENDPOINTS_REGEX_SYMBOL_STAR,
    AWS_ENDPOINTS_REGEX_SYMBOL_PLUS,
    AWS_ENDPOINTS_REGEX_SYMBOL_DIGIT,
    AWS_ENDPOINTS_REGEX_SYMBOL_ALPHA,
    AWS_ENDPOINTS_REGEX_SYMBOL_CHAR,
    AWS_ENDPOINTS_REGEX_SYMBOL_ALTERNATION_GROUP,
};

struct aws_endpoint_regex_symbol {
    enum regex_symbol_type type;

    union {
        uint8_t ch;
        struct aws_string *alternation;
    } info;
};

/* Somewhat arbitrary limits on size of regex and text to avoid overly large
 * inputs. */
static size_t s_max_regex_length = 60;
static size_t s_max_text_length = 50;

static void s_clean_up_symbols(struct aws_array_list *symbols) {
    for (size_t i = 0; i < aws_array_list_length(symbols); ++i) {
        struct aws_endpoint_regex_symbol *element = NULL;
        aws_array_list_get_at_ptr(symbols, (void **)&element, i);

        if (element->type == AWS_ENDPOINTS_REGEX_SYMBOL_ALTERNATION_GROUP) {
            aws_string_destroy(element->info.alternation);
        }
    }
}

struct aws_endpoint_regex *aws_endpoint_regex_new_from_string(
    struct aws_allocator *allocator,
    struct aws_byte_cursor regex_pattern) {

    if (regex_pattern.len == 0 || regex_pattern.len > s_max_regex_length) {
        AWS_LOGF_ERROR(
            AWS_LS_SDKUTILS_ENDPOINTS_REGEX,
            "Invalid regex pattern size. Must be between 1 and %zu",
            s_max_regex_length);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    if (regex_pattern.ptr[0] != '^' || regex_pattern.ptr[regex_pattern.len - 1] != '$') {
        AWS_LOGF_ERROR(
            AWS_LS_SDKUTILS_ENDPOINTS_REGEX,
            "Unsupported regex pattern. Supported patterns must match the whole text.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_UNSUPPORTED_REGEX);
        return NULL;
    }

    /* Ignore begin/end chars */
    aws_byte_cursor_advance(&regex_pattern, 1);
    --regex_pattern.len;

    struct aws_array_list *symbols = aws_mem_calloc(allocator, 1, sizeof(struct aws_array_list));
    aws_array_list_init_dynamic(symbols, allocator, regex_pattern.len, sizeof(struct aws_endpoint_regex_symbol));

    while (regex_pattern.len > 0) {
        uint8_t ch = regex_pattern.ptr[0];
        aws_byte_cursor_advance(&regex_pattern, 1);

        struct aws_endpoint_regex_symbol symbol;
        switch (ch) {
            case '.':
                symbol.type = AWS_ENDPOINTS_REGEX_SYMBOL_DOT;
                break;
            case '*':
                symbol.type = AWS_ENDPOINTS_REGEX_SYMBOL_STAR;
                break;
            case '+':
                symbol.type = AWS_ENDPOINTS_REGEX_SYMBOL_PLUS;
                break;
            case '\\':
                switch (regex_pattern.ptr[0]) {
                    /* Predefined patterns */
                    case 'd':
                        symbol.type = AWS_ENDPOINTS_REGEX_SYMBOL_DIGIT;
                        break;
                    case 'w':
                        symbol.type = AWS_ENDPOINTS_REGEX_SYMBOL_ALPHA;
                        break;

                    /* Escaped chars, ex. * or + */
                    default:
                        symbol.type = AWS_ENDPOINTS_REGEX_SYMBOL_CHAR;
                        symbol.info.ch = regex_pattern.ptr[0];
                        break;
                }
                aws_byte_cursor_advance(&regex_pattern, 1);
                break;
            case '(': {
                struct aws_byte_cursor group = {0};
                if (!aws_byte_cursor_next_split(&regex_pattern, ')', &group)) {
                    AWS_LOGF_ERROR(
                        AWS_LS_SDKUTILS_ENDPOINTS_REGEX, "Invalid regex pattern. Missing closing parenthesis.");
                    aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
                    goto on_error;
                }

                aws_byte_cursor_advance(&regex_pattern, group.len);
                if (regex_pattern.len == 0 || regex_pattern.ptr[0] != ')') {
                    AWS_LOGF_ERROR(
                        AWS_LS_SDKUTILS_ENDPOINTS_REGEX, "Invalid regex pattern. Missing closing parenthesis.");
                    aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
                    goto on_error;
                }
                aws_byte_cursor_advance(&regex_pattern, 1);

                if (group.len == 0) {
                    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_REGEX, "Invalid regex pattern. Empty group.");
                    aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
                    goto on_error;
                }

                /* Verify that group is only used for alternation. */
                for (size_t i = 0; i < group.len; ++i) {
                    if (!aws_isalnum(group.ptr[i]) && group.ptr[i] != '|') {
                        AWS_LOGF_ERROR(
                            AWS_LS_SDKUTILS_ENDPOINTS_REGEX,
                            "Unsupported regex pattern. Only alternation groups are supported.");
                        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_UNSUPPORTED_REGEX);
                        goto on_error;
                    }
                }

                symbol.type = AWS_ENDPOINTS_REGEX_SYMBOL_ALTERNATION_GROUP;
                symbol.info.alternation = aws_string_new_from_cursor(allocator, &group);
                break;
            }

            default: {
                if (!aws_isalnum(ch)) {
                    AWS_LOGF_ERROR(
                        AWS_LS_SDKUTILS_ENDPOINTS_REGEX, "Unsupported regex pattern. Unknown character %c", ch);
                    aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_UNSUPPORTED_REGEX);
                    goto on_error;
                }

                symbol.type = AWS_ENDPOINTS_REGEX_SYMBOL_CHAR;
                symbol.info.ch = ch;
                break;
            }
        }

        aws_array_list_push_back(symbols, &symbol);
    }

    return (struct aws_endpoint_regex *)symbols;

on_error:
    s_clean_up_symbols(symbols);
    aws_array_list_clean_up(symbols);
    aws_mem_release(allocator, symbols);
    return NULL;
}

void aws_endpoint_regex_destroy(struct aws_endpoint_regex *regex) {
    if (regex == NULL) {
        return;
    }

    struct aws_array_list *symbols = (struct aws_array_list *)regex;

    struct aws_allocator *allocator = symbols->alloc;
    s_clean_up_symbols(symbols);
    aws_array_list_clean_up(symbols);
    aws_mem_release(allocator, symbols);
}

static bool s_match_one(struct aws_endpoint_regex_symbol *symbol, struct aws_byte_cursor *text) {
    uint8_t ch = text->ptr[0];
    switch (symbol->type) {
        case AWS_ENDPOINTS_REGEX_SYMBOL_ALPHA:
            return aws_isalpha(ch);
        case AWS_ENDPOINTS_REGEX_SYMBOL_DIGIT:
            return aws_isdigit(ch);
        case AWS_ENDPOINTS_REGEX_SYMBOL_CHAR:
            return ch == symbol->info.ch;
        case AWS_ENDPOINTS_REGEX_SYMBOL_DOT:
            return true;
        default:
            AWS_FATAL_ASSERT(true);
    }

    return false;
}

static bool s_match_star(struct aws_endpoint_regex_symbol *symbol, struct aws_byte_cursor *text) {
    while (s_match_one(symbol, text)) {
        aws_byte_cursor_advance(text, 1);
    }

    return true;
}

static bool s_match_plus(struct aws_endpoint_regex_symbol *symbol, struct aws_byte_cursor *text) {
    if (!s_match_one(symbol, text)) {
        return false;
    }

    aws_byte_cursor_advance(text, 1);
    return s_match_star(symbol, text);
}

int aws_endpoint_regex_match(struct aws_endpoint_regex *regex, struct aws_byte_cursor text) {
    AWS_PRECONDITION(regex);

    if (text.len == 0 || text.len > s_max_text_length) {
        AWS_LOGF_ERROR(
            AWS_LS_SDKUTILS_ENDPOINTS_REGEX, "Invalid text size. Must be between 1 and %zu", s_max_text_length);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_array_list *symbols = (struct aws_array_list *)regex;

    for (size_t i = 0; i < aws_array_list_length(symbols); ++i) {
        struct aws_endpoint_regex_symbol *symbol = NULL;
        aws_array_list_get_at_ptr(symbols, (void **)&symbol, i);

        /* looks forward to check if symbol has * or + modifier */
        if (i + 1 < aws_array_list_length(symbols)) {
            struct aws_endpoint_regex_symbol *next_symbol = NULL;
            aws_array_list_get_at_ptr(symbols, (void **)&next_symbol, i + 1);

            if (next_symbol->type == AWS_ENDPOINTS_REGEX_SYMBOL_STAR ||
                next_symbol->type == AWS_ENDPOINTS_REGEX_SYMBOL_PLUS) {
                if (next_symbol->type == AWS_ENDPOINTS_REGEX_SYMBOL_STAR && !s_match_star(symbol, &text)) {
                    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_REGEX_NO_MATCH);
                } else if (next_symbol->type == AWS_ENDPOINTS_REGEX_SYMBOL_PLUS && !s_match_plus(symbol, &text)) {
                    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_REGEX_NO_MATCH);
                }
                ++i;
                continue;
            }
        }

        switch (symbol->type) {
            case AWS_ENDPOINTS_REGEX_SYMBOL_ALTERNATION_GROUP: {
                struct aws_byte_cursor variant = {0};
                struct aws_byte_cursor alternation = aws_byte_cursor_from_string(symbol->info.alternation);
                size_t chars_in_match = 0;
                while (aws_byte_cursor_next_split(&alternation, '|', &variant)) {
                    if (aws_byte_cursor_starts_with(&text, &variant)) {
                        chars_in_match = variant.len;
                        break;
                    }
                }

                if (chars_in_match == 0) {
                    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_REGEX_NO_MATCH);
                }
                aws_byte_cursor_advance(&text, chars_in_match);
                break;
            }
            default:
                if (!s_match_one(symbol, &text)) {
                    return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_REGEX_NO_MATCH);
                }
                aws_byte_cursor_advance(&text, 1);
                break;
        }
    }

    return AWS_OP_SUCCESS;
}
