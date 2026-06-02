# aws-chunked Decoder Test Vectors

`aws_chunked_decode_tests.json` is the source of truth for test vectors. It can be shared across SDK implementations.

## Regenerating C test vectors

```
python3 generate_test_vectors.py aws_chunked_decode_tests.json > ../../aws_chunked_decoder_test_vectors.inc
```

Run from this directory, or adjust paths accordingly.
