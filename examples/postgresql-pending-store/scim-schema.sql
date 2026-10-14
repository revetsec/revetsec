-- Copyright 2026 Revetware LLC. Apache-2.0. Application fixture profile, not core storage.
CREATE TABLE scim_fixture_tenant (tenant varchar(128) PRIMARY KEY);
CREATE TABLE scim_fixture_resource (
  tenant varchar(128) NOT NULL REFERENCES scim_fixture_tenant,
  id varchar(128) NOT NULL,
  kind varchar(5) NOT NULL CHECK (kind IN ('User','Group')),
  user_name varchar(256), name_key varchar(256), display_name varchar(256), active boolean,
  version bigint NOT NULL CHECK (version > 0), created varchar(64) NOT NULL, modified varchar(64) NOT NULL,
  PRIMARY KEY (tenant,id),
  CHECK ((kind='User' AND user_name IS NOT NULL AND name_key IS NOT NULL) OR (kind='Group' AND display_name IS NOT NULL AND user_name IS NULL AND name_key IS NULL))
);
CREATE UNIQUE INDEX scim_fixture_user_name ON scim_fixture_resource(tenant,name_key) WHERE kind='User';
CREATE TABLE scim_fixture_member (
  tenant varchar(128) NOT NULL, group_id varchar(128) NOT NULL, ordinal integer NOT NULL CHECK (ordinal >= 0 AND ordinal < 128), user_id varchar(128) NOT NULL,
  PRIMARY KEY (tenant,group_id,ordinal), UNIQUE (tenant,group_id,user_id),
  FOREIGN KEY (tenant,group_id) REFERENCES scim_fixture_resource(tenant,id),
  FOREIGN KEY (tenant,user_id) REFERENCES scim_fixture_resource(tenant,id)
);
-- Provision tenant rows with migrations. Every writer must take the same tenant row lock.
-- Group/type and user-reference checks are application-enforced under that lock.
