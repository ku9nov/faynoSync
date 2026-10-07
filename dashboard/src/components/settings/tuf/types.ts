export type StepStatus = 'ready' | 'in-progress' | 'success' | 'error' | 'waiting' | 'disabled';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | { [key: string]: JsonValue } | JsonValue[];

export type TaskResult = {
  message?: string;
  status?: boolean;
  task?: string;
  last_update?: string;
  error?: string;
  [key: string]: JsonValue | undefined;
};

export type TufHistoryEntry = {
  id: string;
  timestamp: string;
  appName: string;
  operation: 'generate' | 'bootstrap' | 'bootstrap-recovery' | 'publish' | 'unsign' | 'update-config' | 'root-meta-update' | 'metadata-update';
  status: 'success' | 'failed' | 'pending';
  taskId?: string;
  result?: TaskResult;
  version?: string;
};

export type TaskState = 'PENDING' | 'SUCCESS' | 'FAILURE';

export type TaskData = {
  task_id: string;
  state: TaskState;
  result?: TaskResult;
};

export type TufConfig = {
  bootstrap: string;
  role_expiration: number;
  root_expiration: number;
  root_num_keys: number;
  root_threshold: number;
  snapshot_expiration: number;
  snapshot_num_keys: number;
  snapshot_threshold: number;
  targets_expiration: number;
  targets_num_keys: number;
  targets_online_key: number;
  targets_threshold: number;
  timestamp_expiration: number;
  timestamp_num_keys: number;
  timestamp_threshold: number;
};
