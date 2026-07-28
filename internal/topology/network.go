package topology

type Network struct {
	ID              string
	Name            string
	Status          string
	External        bool
	MTU             int
	NetworkType     string
	PhysicalNetwork string
	SegmentationID  string
	SubnetIDs       []string
}
