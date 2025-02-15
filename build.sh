#!/usr/bin/env bash
# Provide output filepath (.json) as first argument when invoking this script

build_dir="build";
rm -rf "${build_dir}";
mkdir "${build_dir}";
cp -r assets/* "${build_dir}"

cat > "${build_dir}/properties.json" <<-EOF
{
    "endpointId": "${ID}",
    "OneSignalAppId": {
        "formonit": "${ONESIGNAL_APP_ID_FORMONIT}"
    },
    "dataTtl": "${TTL} seconds",
    "cdnTtl": "${CDN_TTL} days",
    "limits": {
        "size": "${BODYLIMIT} bytes per request",
        "rate": "${RATELIMIT} requests / ${RATELIMIT_WINDOW} seconds"
    }
}
EOF

echo "Static files generated at directory: ${build_dir}/"
