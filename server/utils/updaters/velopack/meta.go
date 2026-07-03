package velopack

const UpdaterType = "velopack"

type VelopackMeta struct {
	Type     string `bson:"type"`
	FileName string `bson:"file_name"`
	SHA1     string `bson:"sha1"`
	SHA256   string `bson:"sha256"`
	Size     int64  `bson:"size"`
}
