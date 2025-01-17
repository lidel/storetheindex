package config

// Datastore tracks the configuration of the datastore.
type Datastore struct {
	// Dir is the directory where the datastore is kept. If this is not an
	// absolute path then the location is relative to the indexer repo
	// directory.
	Dir string
	// DirAdvertisements specifies to keep advertisements in a separate
	// datastore directory, using a separate datastore instance. If this is not
	// set or is set to the same value as Dir, then the same datastore instance
	// is used to store advertisements. If this is not an absolute path then
	// the location is relative to the indexer repo directory.
	DirAdvertisements string
	// Type is the type of datastore.
	Type string
}

// NewDatastore returns Datastore with values set to their defaults.
func NewDatastore() Datastore {
	return Datastore{
		Dir:  "datastore",
		Type: "levelds",
	}
}

// populateUnset replaces zero-values in the config with default values.
func (c *Datastore) populateUnset() {
	def := NewDatastore()

	if c.Dir == "" {
		c.Dir = def.Dir
	}
	if c.Type == "" {
		c.Type = def.Type
	}
}
