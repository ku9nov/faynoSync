package sparkle

const UpdaterType = "sparkle"

const (
	KindFull  = "full"
	KindDelta = "delta"
)

// SparkleMeta is one artifact's Sparkle metadata, stored verbatim from the
// uploaded appcast so it can be re-emitted on materialization. Kind separates a
// full archive from a delta (nested <sparkle:deltas> enclosure).
type SparkleMeta struct {
	FileName    string `bson:"file_name"`
	Kind        string `bson:"kind"`
	EdSignature string `bson:"ed_signature,omitempty"`
	Length      int64  `bson:"length,omitempty"`
	Type        string `bson:"type,omitempty"`
	// full-only:
	SparkleVersion        string `bson:"sparkle_version,omitempty"` // CFBundleVersion
	ShortVersionString    string `bson:"short_version_string,omitempty"`
	MinimumSystemVersion  string `bson:"minimum_system_version,omitempty"`
	PhasedRolloutInterval string `bson:"phased_rollout_interval,omitempty"` // native, pass-through
	// delta-only (from <sparkle:deltas> nested enclosure):
	DeltaFrom               string `bson:"delta_from,omitempty"`
	DeltaFromExecutableSize string `bson:"delta_from_executable_size,omitempty"`
	DeltaFromLocales        string `bson:"delta_from_locales,omitempty"`
}
