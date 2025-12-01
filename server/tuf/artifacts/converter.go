package artifacts

import (
	"fmt"

	"faynoSync/server/model"
	tuf_utils "faynoSync/server/tuf/utils"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func ConvertMongoArtifactToTUF(
	mongoArtifact model.Artifact,
	checkAppVisibility bool,
	env *viper.Viper,
) (*Artifact, error) {
	tufPath, err := tuf_utils.ExtractTUFPathFromLink(mongoArtifact.Link, checkAppVisibility, env)
	if err != nil {
		logrus.Errorf("Failed to extract TUF path from link %s: %v", mongoArtifact.Link, err)
		return nil, fmt.Errorf("failed to extract TUF path: %w", err)
	}

	if len(mongoArtifact.Hashes) == 0 {
		return nil, fmt.Errorf("artifact has no hashes (required for TUF)")
	}

	if mongoArtifact.Length == 0 {
		return nil, fmt.Errorf("artifact has no length (required for TUF)")
	}

	artifactInfo := ArtifactInfo{
		Length: mongoArtifact.Length,
		Hashes: mongoArtifact.Hashes,
		Custom: nil,
	}

	tufArtifact := &Artifact{
		Info: artifactInfo,
		Path: tufPath,
	}

	logrus.Debugf("Converted MongoDB artifact to TUF artifact: path=%s, length=%d, hashes=%v",
		tufPath, mongoArtifact.Length, mongoArtifact.Hashes)

	return tufArtifact, nil
}
