package artifacts

import "time"

type ArtifactInfo struct {
	Length int64                  `json:"length"`
	Hashes map[string]string      `json:"hashes"`
	Custom map[string]interface{} `json:"custom,omitempty"`
}

type Artifact struct {
	Info ArtifactInfo `json:"info"`
	Path string       `json:"path"`
}

type AddArtifactsPayload struct {
	Artifacts         []Artifact `json:"artifacts"`
	AddTaskIDToCustom *bool      `json:"add_task_id_to_custom,omitempty"`
	PublishArtifacts  *bool      `json:"publish_artifacts,omitempty"`
}

type DeleteArtifactsPayload struct {
	Artifacts        []string `json:"artifacts"`
	PublishArtifacts bool     `json:"publish_artifacts,omitempty"`
}

type ArtifactsResponse struct {
	Data struct {
		Artifacts  []string  `json:"artifacts"`
		TaskID     string    `json:"task_id"`
		LastUpdate time.Time `json:"last_update"`
	} `json:"data"`
	Message string `json:"message"`
}
