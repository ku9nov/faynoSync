export interface PresignedUploadScriptOptions {
  apiURL: string;
  appName: string;
  channel: string;
  platform: string;
  arch: string;
  updater: string;
  publish: boolean;
  critical: boolean;
  tuf: boolean;
}

export const PRESIGNED_UPLOADS_DOCS_URL = 'https://faynosync.com/docs/presigned-uploads';

export const SCRIPT_FILE_NAME = 'faynosync-upload.sh';

const API_PLACEHOLDER = 'https://faynosync.example.com';

const quote = (value: string): string => `'${value.replace(/'/g, `'\\''`)}'`;

const shellArg = (value: string): string => (/^[A-Za-z0-9._/:@-]+$/.test(value) ? value : quote(value));

export const feedFilePlaceholder = (updater: string, channel: string): string | null => {
  switch (updater) {
    case 'velopack':
      return `releases.${channel || 'CHANNEL'}.json`;
    case 'sparkle':
      return 'appcast.xml';
    case 'squirrel_windows':
      return 'RELEASES';
    case 'electron-builder':
      return 'latest.yml';
    default:
      return null;
  }
};

export const generatePresignedUploadScript = (options: PresignedUploadScriptOptions): string => {
  const { appName, channel, platform, arch, updater, publish, critical, tuf } = options;
  const apiURL = options.apiURL?.trim().replace(/\/+$/, '') || API_PLACEHOLDER;
  const feed = feedFilePlaceholder(updater, channel);

  const exampleArgs = ['--version 1.4.0'];
  if (feed) exampleArgs.push(`--feed ${shellArg(`path/to/${feed}`)}`);
  if (updater === 'tauri') exampleArgs.push('--signature "$(cat path/to/artifact.sig)"');
  exampleArgs.push('path/to/artifact-1 path/to/artifact-2');

  const defaults = [
    channel && `--channel ${shellArg(channel)}`,
    platform && `--platform ${shellArg(platform)}`,
    arch && `--arch ${shellArg(arch)}`,
    updater && `--updater ${shellArg(updater)}`,
    publish ? '--publish' : '--no-publish',
    critical ? '--critical' : '--no-critical',
  ].filter(Boolean);

  const manifestArgs = tuf
    ? [
        '--arg n "$(basename "$f")"',
        '--arg md5 "$(digest md5 "$f")"',
        '--arg sha256 "$(digest sha256 "$f")"',
        '--arg sha512 "$(digest sha512 "$f")"',
        `--argjson length "$(wc -c < "$f" | tr -d ' ')"`,
        `'{name:$n, md5:$md5, sha256:$sha256, sha512:$sha512, length:$length}'`,
      ]
    : ['--arg n "$(basename "$f")"', '--arg md5 "$(digest md5 "$f")"', `'{name:$n, md5:$md5}'`];

  const continued = (lines: string[], indent: string): string => lines.join(` \\\n${indent}`);

  return `#!/usr/bin/env bash
# faynoSync presigned upload for ${appName}${tuf ? ' (TUF: sends sha256/sha512)' : ''}
# Requires curl >= 7.76, jq, openssl. Docs: ${PRESIGNED_UPLOADS_DOCS_URL}
#
# Usage:
#   export FAYNOSYNC_TOKEN=<ci-cd-token>
#   ./${SCRIPT_FILE_NAME} ${continued(exampleArgs, '#     ')}
#
# Defaults picked in the dashboard, override any of them per run:
#   ${defaults.join(' ')}
#
# Options:
#   --version <version>        required
#   --channel, --platform, --arch, --updater <value>
#   --publish | --no-publish   applied only when this upload creates the version
#   --critical | --no-critical applied only when this upload creates the version
#   --changelog <markdown>     applied only when this upload creates the version
#   --feed <file>              required for velopack, sparkle, squirrel_windows, electron-builder
#   --signature <signature>    required for tauri
#   <file>...                  artifacts sent directly to object storage
#
# One run uploads one platform/architecture. For a multi-platform release run it once per
# platform with the same --version and --channel.
set -euo pipefail

API=${quote(apiURL)}
APP_NAME=${quote(appName)}
TOKEN="\${FAYNOSYNC_TOKEN:?set FAYNOSYNC_TOKEN to a faynoSync CI/CD token}"

VERSION=''
CHANNEL=${quote(channel)}
PLATFORM=${quote(platform)}
ARCH=${quote(arch)}
UPDATER=${quote(updater)}
PUBLISH=${publish}
CRITICAL=${critical}
CHANGELOG=''
FEED=''
SIGNATURE=''

die() { echo "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="\${2:?$1 needs a value}"; shift 2 ;;
    --channel) CHANNEL="\${2:?$1 needs a value}"; shift 2 ;;
    --platform) PLATFORM="\${2:?$1 needs a value}"; shift 2 ;;
    --arch) ARCH="\${2:?$1 needs a value}"; shift 2 ;;
    --updater) UPDATER="\${2:?$1 needs a value}"; shift 2 ;;
    --changelog) CHANGELOG="\${2?$1 needs a value}"; shift 2 ;;
    --feed) FEED="\${2:?$1 needs a value}"; shift 2 ;;
    --signature) SIGNATURE="\${2:?$1 needs a value}"; shift 2 ;;
    --publish) PUBLISH=true; shift ;;
    --no-publish) PUBLISH=false; shift ;;
    --critical) CRITICAL=true; shift ;;
    --no-critical) CRITICAL=false; shift ;;
    --) shift; break ;;
    -*) die "unknown option: $1 (see the header of $0)" ;;
    *) break ;;
  esac
done

[ -n "$VERSION" ] || die "--version is required (see the header of $0)"
[ $# -gt 0 ] || die "no files to upload (see the header of $0)"
for f in "$@"; do [ -f "$f" ] || die "not a file: $f"; done
case "$UPDATER" in
  velopack|sparkle|squirrel_windows|electron-builder) [ -n "$FEED" ] || die "--updater $UPDATER needs --feed <feed file>" ;;
  tauri) [ -n "$SIGNATURE" ] || die "--updater tauri needs --signature <contents of the .sig file>" ;;
esac

digest() { openssl "$1" -r "$2" | cut -d' ' -f1; }

manifest=$(for f in "$@"; do
  jq -nc ${continued(manifestArgs, '    ')}
done | jq -sc .)

data=$(jq -nc \\
  --arg app_name "$APP_NAME" --arg version "$VERSION" --arg channel "$CHANNEL" \\
  --arg platform "$PLATFORM" --arg arch "$ARCH" --arg updater "$UPDATER" \\
  --arg signature "$SIGNATURE" --arg changelog "$CHANGELOG" \\
  --argjson publish "$PUBLISH" --argjson critical "$CRITICAL" \\
  '{app_name:$app_name, version:$version, channel:$channel, platform:$platform, arch:$arch, updater:$updater,
    signature:$signature, publish:$publish, critical:$critical, changelog:$changelog}
   | with_entries(select(.value != ""))')

init_args=(-H "Authorization: Bearer $TOKEN" --form-string "data=$data" --form-string "files=$manifest")
[ -z "$FEED" ] || init_args+=(-F "file=@$FEED")

# 1. init: every check runs here, before any byte is transferred
init_rc=0
init=$(curl -sS --fail-with-body -w '\\n%{http_code}' -X POST "$API/upload/init" "\${init_args[@]}") || init_rc=$?
status=\${init##*$'\\n'}
init=\${init%$'\\n'*}
if [ "$init_rc" -ne 0 ]; then
  if [ "$status" = "501" ]; then
    die "upload/init: this faynoSync storage driver does not support presigned uploads (MinIO). Use POST /upload instead."
  fi
  die "upload/init failed (HTTP $status): $init"
fi
upload_id=$(jq -r .upload_id <<<"$init")

# 2. PUT every file directly to storage with the headers returned by init, verbatim
for f in "$@"; do
  name=$(basename "$f")
  url=$(jq -r --arg n "$name" '.files[] | select(.name==$n) | .url' <<<"$init")
  headers=()
  while IFS= read -r h; do headers+=(-H "$h"); done < <(
    jq -r --arg n "$name" '.files[] | select(.name==$n) | .headers | to_entries[] | "\\(.key): \\(.value)"' <<<"$init")
  echo "Uploading $name" >&2
  curl -sS --fail-with-body -X PUT "\${headers[@]}" --upload-file "$f" "$url" > /dev/null
done

# 3. complete: verifies what storage received and creates the version
curl -sS --fail-with-body -X POST "$API/upload/complete" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d "$(jq -nc --arg id "$upload_id" '{upload_id:$id}')"
echo
`;
};
