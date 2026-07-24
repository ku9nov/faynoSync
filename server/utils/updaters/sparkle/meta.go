package sparkle

const UpdaterType = "sparkle"

const (
	KindFull  = "full"
	KindDelta = "delta"
)

// SparkleMeta is one artifact's Sparkle metadata. To reach full parity with
// vanilla Sparkle, the whole <item> is preserved verbatim (RawItem) on the full
// artifact and re-emitted on materialization with only faynoSync-managed fields
// overlaid. Only what faynoSync actually computes on stays typed: SparkleVersion
// (sorting) and FileName (enclosure basename → artifact link matching).
type SparkleMeta struct {
	FileName       string `bson:"file_name"`
	Kind           string `bson:"kind"`
	SparkleVersion string `bson:"sparkle_version,omitempty"` // CFBundleVersion, full only
	RawItem        string `bson:"raw_item,omitempty"`        // verbatim <item> XML, full only
}
