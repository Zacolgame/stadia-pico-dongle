#!/system/bin/sh
# nul-test: does toybox printf emit \x00 or truncate?
printf '\x16\xfe\xfd\x00\x00\x41\x42' | od -A d -t x1
echo "bytes_above_should_be_7"
