import { normalizeKeyAlgorithm } from '@/components/settings/tuf/keyAlgorithm';

interface TufKmsCommandParams {
  appName: string;
  keyType: string;
  roleName: string;
  adminName: string;
  metadataUrl?: string;
  expiration: {
    root: number;
    timestamp: number;
    snapshot: number;
    targets: number;
  };
  thresholds: {
    root: number;
    timestamp: number;
    snapshot: number;
    targets: number;
    delegation: number;
  };
}

const quote = (value: string): string => `'${value.replace(/'/g, `'\\''`)}'`;

export const generateTufKmsCommands = (params: TufKmsCommandParams): string => {
  const { appName, keyType, roleName, adminName, metadataUrl, expiration, thresholds } = params;
  const algorithm = normalizeKeyAlgorithm(keyType);

  const initArgs = [
    `--app ${quote(appName)}`,
    `--admin ${quote(adminName)}`,
    `--key-type ${algorithm}`,
  ];
  if (metadataUrl?.trim()) {
    initArgs.push(`--metadata-url ${quote(metadataUrl.trim())}`);
  }

  const bootstrapArgs = [
    `--role ${quote(roleName)}`,
    `--root-threshold ${thresholds.root} --root-expiration ${expiration.root}`,
    `--targets-threshold ${thresholds.targets} --targets-expiration ${expiration.targets}`,
    `--snapshot-threshold ${thresholds.snapshot} --snapshot-expiration ${expiration.snapshot}`,
    `--timestamp-threshold ${thresholds.timestamp} --timestamp-expiration ${expiration.timestamp}`,
    `--delegation-threshold ${thresholds.delegation}`,
  ];

  const block = (command: string, args: string[]): string =>
    `${command} \\\n${args.map((arg) => `  ${arg}`).join(' \\\n')}`;

  return [block('tuf-kms init', initArgs), block('tuf-kms bootstrap generate', bootstrapArgs)].join('\n\n');
};
