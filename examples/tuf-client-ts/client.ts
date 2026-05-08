import fs from 'fs';
import path from 'path';
import { Updater } from 'tuf-js';

const target = 'tuf-admin/nightly/darwin/arm64/tuf-0.0.0.2';

const baseURL = 'http://cb-faynosync-s3-public.web.garage.localhost:3902';
const metadataBaseUrl = `${baseURL}/tuf_metadata/admin/tuf`;

// Same layout as the Go example: cwd/tmp for metadata, cwd/tmp/download for targets.
const tmpDir = path.join(process.cwd(), 'tmp');
const metadataDir = tmpDir;
const targetDir = path.join(tmpDir, 'download');

function initDirs() {
  if (!fs.existsSync(tmpDir)) {
    fs.mkdirSync(tmpDir, { mode: 0o750 });
  }
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { mode: 0o750 });
  }
}

/** Trust-on-first-use: bootstrap local root.json from remote 1.root.json (same as go-tuf example). */
async function initTrustOnFirstUse() {
  const rootFilePath = path.join(metadataDir, 'root.json');
  if (fs.existsSync(rootFilePath)) {
    return;
  }

  const rootMetadataUrl = new URL(
    '1.root.json',
    metadataBaseUrl.endsWith('/') ? metadataBaseUrl : `${metadataBaseUrl}/`
  );

  const res = await fetch(rootMetadataUrl);
  if (!res.ok) {
    throw new Error(
      `Failed to download initial root from ${rootMetadataUrl}: ${res.status} ${res.statusText}`
    );
  }

  const buf = Buffer.from(await res.arrayBuffer());
  fs.writeFileSync(rootFilePath, buf, { mode: 0o644 });
}

async function downloadTarget() {
  const updater = new Updater({
    metadataBaseUrl,
    targetBaseUrl: baseURL,
    metadataDir,
    targetDir,
    config: {
      // faynoSync serves targets without the consistent-snapshot hash prefix in the path (see go example).
      prefixTargetsWithHash: false,
    },
  });

  await updater.refresh();

  const targetInfo = await updater.getTargetInfo(target);

  if (!targetInfo) {
    console.log(`Target ${target} doesn't exist`);
    return;
  }
  const targetPath = await updater.findCachedTarget(targetInfo);
  if (targetPath) {
    console.log(`Target ${target} is cached at ${targetPath}`);
    return;
  }

  const targetFile = await updater.downloadTarget(targetInfo);
  console.log(`Target ${target} downloaded to ${targetFile}`);
}

async function main() {
  initDirs();
  await initTrustOnFirstUse();
  await downloadTarget();
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
