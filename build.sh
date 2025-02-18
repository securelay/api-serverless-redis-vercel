#!/usr/bin/env bash
# Provide output filepath (.json) as first argument when invoking this script

build_dir="build";
rm -rf "${build_dir}";
mkdir "${build_dir}";
cp -r assets/* "${build_dir}"

id="$(npm run id | tail -n1)";

echo "${id}" > "${build_dir}/id.txt"

cat > "${build_dir}/properties.json" <<-EOF
{
    "id": "${id}",
    "OneSignalAppId": {
        "formonit": "${ONESIGNAL_APP_ID_FORMONIT}"
    },
    "dataTtl": "${TTL} seconds",
    "cdnTtl": "${CDN_TTL} days",
    "limits": {
        "size": "${BODYLIMIT} bytes per request",
        "rate": "${RATELIMIT} requests / ${RATELIMIT_WINDOW} seconds",
        "maxMessagesRetained": "${MAX_PUBLIC_POSTS_RETAINED}",
        "maxKeyValFields": "${MAX_PRIVATE_POST_FIELDS}"
    }
}
EOF

echo "Static files generated at directory: ${build_dir}/"
