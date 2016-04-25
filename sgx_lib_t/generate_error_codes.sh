SGX_ERROR_H='sgx_error.h'
REGEX='match($0, /SGX_ERROR_([^ ]*).*= SGX_MK_ERROR\(([0-9a-z]+)\)[^(\/\*)]*\/\* ([^\*)]*)/, a) {print "case", a[2], ": return \"" a[1], a[3] "\";"}'
OUT='util_error'
OUT_C="$OUT.cpp"

echo "#include \"$OUT.h\"" > $OUT_C
echo 'char* get_error_description(int error_code) {' >> $OUT_C
echo 'switch (error_code) {' >> $OUT_C
cat sgx_error.h | awk "$REGEX" >> $OUT_C
echo 'default : return "unknown error code";' >> $OUT_C
echo '}}' >> $OUT_C