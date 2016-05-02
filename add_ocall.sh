#!/bin/bash
# input: add_ocall.sh <.edl style method signature>
# for example `void rewind([user_check] FILE* file);`
# formatting of pointer types: `type* name` (asterisk right after type, without a space inbetween)
# HOOK_IN_FILE (where to place generated code) can be overridden by an environment variable with that name

ENCLAVE_DIR="${ENCLAVE_DIR:-sgx_lib_t}"
APP_DIR="${APP_DIR:-sgx_lib_u}"
EDL="$ENCLAVE_DIR/${EDL:-sgx_lib.edl}"
TRUSTED_C="$ENCLAVE_DIR/${TRUSTED_C:-sgx_lib_ocall.c}"
TRUSTED_H="$ENCLAVE_DIR/${TRUSTED_H:-sgx_lib_ocall.h}"
UNTRUSTED_C="$APP_DIR/util_u.c"

FUNC=$1
HOOK_IN_FILE=${HOOK_IN_FILE:-"\/\* GENERATE OCALL CODE AFTER THIS LINE \*\/"}

function join { local d=$1; shift; echo -n "$1"; shift; printf "%s" "${@/#/$d}"; }

####################################
# STEP 1: parse the method signature
####################################

# get return type
RET=$(grep -Eo '^[^[:blank:]]+' <<< $FUNC)

# get function name
NAME=$(grep -Eo '([^ ])+\(' <<< $FUNC | head -c-2)

# get params all in one string
PARAMS=$(grep -Eo '\([^\)]*' <<< $FUNC | cut -c 2-)

# get signature without .edl [attributes]
FUNC_VANILLA=$(sed 's/\[[^]]*\]//g' <<< $FUNC)

# build $PARAMS_ARRAY
PARAMS_ARRAY=()
PARAM_NAMES_ARRAY=()
while read -r line ; do
	# remove .edl [attributes] and trim special characters
	PARAM=$(awk 'match($0, "(\\[.*\\] )?([^,\\)]*)", a) {print a[2]}' <<< $line)
	PARAMS_ARRAY+=("$PARAM")

	PARAM_NAMES_ARRAY+=($(grep -oE '[^ ]+$' <<< $PARAM))
done <<< "$(echo "$FUNC_VANILLA" | grep -Eo '[^\(,]*[,\)]')"

# output params without .edl [attributes]
PARAMS_VANILLA=$(join ', ' "${PARAMS_ARRAY[@]}")
PARAM_NAMES=$(join ', ' "${PARAM_NAMES_ARRAY[@]}")


#################################
# STEP 2: generate output strings
#################################

NAME_OCALL="${NAME}_ocall"
FUNC_VANILLA="$RET $NAME($PARAMS_VANILLA)" #cleaner version (no superfluous whitespace)
EDL_SIGNATURE="\ \t\t$RET $NAME_OCALL($PARAMS);"
if [ "$RET" != "void" ]; then
	RET_DECLARE="  $RET ret;\n"
	RET_RETURN="  return ret;\n"
	RET_PARAM="&ret, "
	RETURN="return ";
fi
TRUSTED_WRAPPER="$FUNC_VANILLA {\n\
$RET_DECLARE\
  check($NAME_OCALL($RET_PARAM$PARAM_NAMES));\n\
$RET_RETURN\
}\n\
"
UNTRUSTED_WRAPPER="$RET $NAME_OCALL($PARAMS_VANILLA) {\n\
  $RETURN$NAME($PARAM_NAMES);\n\
}\n\
"


#########################
# STEP 3: generate output
#########################

# .edl: output signature with .edl attributes
sed -i "/$HOOK_IN_FILE/a \
$EDL_SIGNATURE" $EDL

# trusted h: output vanilla signature (without .edl attributes)
sed -i "/$HOOK_IN_FILE/a \
$FUNC_VANILLA;" $TRUSTED_H

# trusted c: wrapper to _ocall, with ret parameter
sed -i "/$HOOK_IN_FILE/a \
$TRUSTED_WRAPPER" $TRUSTED_C

# untrusted c: wrapper to backing function
sed -i "/$HOOK_IN_FILE/a \
$UNTRUSTED_WRAPPER" $UNTRUSTED_C
