CREATE FUNCTION path_key(path text) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN sha256(convert_to(path,'UTF8'));
CREATE TABLE identities(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,sha256 bytea NOT NULL UNIQUE CHECK(octet_length(sha256)=32));
CREATE TABLE relative_paths(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,path text NOT NULL);
CREATE UNIQUE INDEX relative_paths_key ON relative_paths(path_key(path));
CREATE TABLE parent_locations(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,sample_id bigint NOT NULL REFERENCES identities(id),path text NOT NULL);
CREATE UNIQUE INDEX parent_locations_key ON parent_locations(sample_id,path_key(path));
CREATE TABLE locations(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 sample_id bigint NOT NULL REFERENCES identities(id),
 parent_sample_id bigint REFERENCES identities(id),
 parent_location_id bigint REFERENCES parent_locations(id),
 relative_path_id bigint REFERENCES relative_paths(id),
 path text,
 full_path_key bytea NOT NULL CHECK(octet_length(full_path_key)=32),
 filename_override text,
 rel text NOT NULL DEFAULT '',source text NOT NULL DEFAULT '',feed text NOT NULL DEFAULT '',ecosystem text NOT NULL DEFAULT '',
 mtime timestamptz,first_seen_at timestamptz NOT NULL DEFAULT now(),last_seen_at timestamptz NOT NULL DEFAULT now(),
 CHECK((parent_location_id IS NULL AND relative_path_id IS NULL AND path IS NOT NULL AND path<>'') OR
       (parent_location_id IS NOT NULL AND relative_path_id IS NOT NULL AND path IS NULL))
);
CREATE UNIQUE INDEX locations_key ON locations(sample_id,full_path_key);
CREATE INDEX locations_child_parents ON locations(sample_id,parent_sample_id,id DESC) WHERE parent_sample_id IS NOT NULL;
CREATE INDEX locations_members ON locations(parent_sample_id) WHERE parent_sample_id IS NOT NULL;
CREATE INDEX locations_containment ON locations(sample_id) WHERE parent_sample_id IS NOT NULL AND rel IN ('','unpacked');
CREATE INDEX locations_donor ON locations(sample_id,path COLLATE "C") WHERE parent_sample_id IS NULL;
CREATE INDEX locations_incoming ON locations(first_seen_at,sample_id,path) WHERE parent_sample_id IS NULL AND path LIKE 'incoming/%';
CREATE VIEW reconstructed AS
 SELECT l.id,encode(s.sha256,'hex') AS sha256,
        coalesce(p.path||'!!'||r.path,l.path) AS path,
        coalesce(encode(parent.sha256,'hex'),'') AS parent_sha256,
        coalesce(l.filename_override,r.path,l.path) AS filename,
        l.rel,l.source,l.feed,l.ecosystem,l.mtime,l.first_seen_at,l.last_seen_at
 FROM locations l JOIN identities s ON s.id=l.sample_id
 LEFT JOIN identities parent ON parent.id=l.parent_sample_id
 LEFT JOIN parent_locations p ON p.id=l.parent_location_id
 LEFT JOIN relative_paths r ON r.id=l.relative_path_id;

-- Baseline: the same identity/observation workload and seven location access
-- paths, using Hopper's actual locationsFromStagingPG supplied by the caller.
-- Analysis, labels and queues are outside BOTH sides of this experiment.
CREATE TABLE samples(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,sha256 text NOT NULL UNIQUE);
CREATE TABLE sample_locations(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 sha256 text NOT NULL REFERENCES samples(sha256),path text NOT NULL CHECK(path<>''),parent_sha256 text NOT NULL DEFAULT '',
 rel text NOT NULL DEFAULT '',filename text NOT NULL DEFAULT '',source text NOT NULL DEFAULT '',feed text NOT NULL DEFAULT '',ecosystem text NOT NULL DEFAULT '',
 mtime timestamptz,first_seen_at timestamptz NOT NULL DEFAULT now(),last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_sl_location_key ON sample_locations(sha256,path_key(path));
CREATE INDEX idx_sl_child_parents ON sample_locations(sha256,parent_sha256,id DESC) WHERE parent_sha256<>'';
CREATE INDEX idx_sl_members ON sample_locations(parent_sha256) WHERE parent_sha256<>'';
CREATE INDEX idx_sl_containment ON sample_locations(sha256) WHERE parent_sha256<>'' AND rel IN ('','unpacked');
CREATE INDEX idx_sl_donor ON sample_locations(sha256,path COLLATE "C") WHERE parent_sha256='';
CREATE INDEX idx_sl_incoming_seen ON sample_locations(first_seen_at,sha256,path) WHERE parent_sha256='' AND path LIKE 'incoming/%';
