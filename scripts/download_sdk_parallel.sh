#!/usr/bin/env bash
# Download the .NET SDK zip with parallel range requests (single-connection
# downloads from builds.dotnet.microsoft.com can be extremely slow on some
# networks; 8 parallel chunks reached ~2 MB/s aggregate on the build machine).
#
# Environment overrides:
#   SDK_VERSION    default 10.0.404
#   DOTNET_DIR     install dir (default: $HOME/.dotnet)
#   OCS_TOOLS_DIR  scratch dir (default: $HOME/AppData/Local/Temp/ocs-setup)
set -euo pipefail

HOME_UNIX="${HOME:-$(cd "$USERPROFILE" && pwd)}"
SDK_VERSION="${SDK_VERSION:-10.0.404}"
DOTNET_DIR="${DOTNET_DIR:-$HOME_UNIX/.dotnet}"
OCS_TOOLS_DIR="${OCS_TOOLS_DIR:-$HOME_UNIX/AppData/Local/Temp/ocs-setup}"
mkdir -p "$OCS_TOOLS_DIR"
cd "$OCS_TOOLS_DIR"

URL="https://builds.dotnet.microsoft.com/dotnet/Sdk/${SDK_VERSION}/dotnet-sdk-${SDK_VERSION}-win-x64.zip"
LEN=$(curl -sI "$URL" | tr -d '\r' | awk 'tolower($1)=="content-length:"{print $2}')
echo "total bytes: $LEN"
N=8
CHUNK=$(( (LEN + N - 1) / N ))
rm -f sdk-part-*
for i in $(seq 0 $((N-1))); do
  START=$((i * CHUNK))
  END=$((START + CHUNK - 1))
  if [ "$END" -ge "$LEN" ]; then END=$((LEN - 1)); fi
  if [ "$START" -ge "$LEN" ]; then break; fi
  curl -s --retry 4 --retry-delay 2 -r "${START}-${END}" -o "sdk-part-$(printf '%02d' "$i")" "$URL" &
done
wait
cat sdk-part-* > dotnet-sdk.zip
ACTUAL=$(stat -c %s dotnet-sdk.zip)
echo "assembled: $ACTUAL (expect $LEN)"
[ "$ACTUAL" = "$LEN" ] || { echo "SIZE MISMATCH"; exit 1; }
rm -f sdk-part-*
mkdir -p "$DOTNET_DIR"
tar -xf dotnet-sdk.zip -C "$DOTNET_DIR"
echo "extracted"
"$DOTNET_DIR/dotnet.exe" --list-sdks
echo "SDK_DONE"