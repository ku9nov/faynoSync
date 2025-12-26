package tasks

import "time"

// TaskState represents the state of a task
type TaskState string

const (
	TaskStatePending  TaskState = "PENDING"
	TaskStateReceived TaskState = "RECEIVED"
	TaskStateStarted  TaskState = "STARTED"
	TaskStateSuccess  TaskState = "SUCCESS"
	TaskStateFailure  TaskState = "FAILURE"
	TaskStateRevoked  TaskState = "REVOKED"
	TaskStateRejected TaskState = "REJECTED"
	TaskStateRetry    TaskState = "RETRY"
	TaskStateIgnored  TaskState = "IGNORED"
	TaskStateErrored  TaskState = "ERRORED"
	TaskStatePreRun   TaskState = "PRE_RUN"
	TaskStateRunning  TaskState = "RUNNING"
)

// TaskName represents the type of task
type TaskName string

const (
	TaskNameAddArtifacts              TaskName = "add_artifacts"
	TaskNameRemoveArtifacts           TaskName = "remove_artifacts"
	TaskNameBootstrap                 TaskName = "bootstrap"
	TaskNameUpdateSettings            TaskName = "update_settings"
	TaskNamePublishArtifacts          TaskName = "publish_artifacts"
	TaskNameMetadataUpdate            TaskName = "metadata_update"
	TaskNameMetadataDelegation        TaskName = "metadata_delegation"
	TaskNameSignMetadata              TaskName = "sign_metadata"
	TaskNameDeleteSignMetadata        TaskName = "delete_sign_metadata"
	TaskNameForceOnlineMetadataUpdate TaskName = "force_online_metadata_update"
)

// TaskResult contains the result of a task execution
type TaskResult struct {
	Message    *string                `json:"message,omitempty"`
	Error      *string                `json:"error,omitempty"`
	Status     *bool                  `json:"status,omitempty"` // true = Success, false = Failure
	Task       *TaskName              `json:"task,omitempty"`
	LastUpdate *time.Time             `json:"last_update,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// TasksData contains task information
type TasksData struct {
	TaskID string      `json:"task_id"`
	State  TaskState   `json:"state"`
	Result *TaskResult `json:"result,omitempty"`
}

// Response is the API response for task status
type Response struct {
	Data    TasksData `json:"data"`
	Message string    `json:"message"`
}

// TaskStatus represents the full task status stored in Redis
type TaskStatus struct {
	State  TaskState   `json:"state"`
	Result *TaskResult `json:"result,omitempty"`
}
