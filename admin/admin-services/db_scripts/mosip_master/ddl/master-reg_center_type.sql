

-- object: master.reg_center_type | type: TABLE --
-- DROP TABLE IF EXISTS master.reg_center_type CASCADE;
CREATE TABLE master.reg_center_type(
	code character varying(36) NOT NULL,
	name character varying(64) NOT NULL,
	descr character varying(128),
	lang_code character varying(3) NOT NULL,
	is_active boolean NOT NULL,
	cr_by character varying(256) NOT NULL,
	cr_dtimes timestamp NOT NULL,
	upd_by character varying(256),
	upd_dtimes timestamp,
	is_deleted boolean NOT NULL DEFAULT FALSE,
	del_dtimes timestamp,
	CONSTRAINT pk_cntrtyp_id PRIMARY KEY (code,lang_code)

);
-- ddl-end --
COMMENT ON TABLE master.reg_center_type IS 'Registration Center Type : List of registration center types availabe / configured within the system.';
-- ddl-end --
COMMENT ON COLUMN master.reg_center_type.code IS 'Code : different types of registration centers, ';
-- ddl-end --
COMMENT ON COLUMN master.reg_center_type.name IS 'Name : Registration center type';
-- ddl-end --
COMMENT ON COLUMN master.reg_center_type.descr IS 'Description : Registration center type description';
-- ddl-end --
COMMENT ON COLUMN master.reg_center_type.lang_code IS 'Language Code : For multilanguage implementation this attribute Refers master.language.code. The value of some of the attributes in current record is stored in this respective language. ';
-- ddl-end --
COMMENT ON COLUMN master.reg_center_type.is_active IS 'IS_Active : Flag to mark whether the record is Active or In-active';
-- ddl-end --
COMMENT ON COLUMN master.reg_center_type.cr_by IS 'Created By : ID or name of the user who create / insert record';
-- ddl-end --
COMMENT ON COLUMN master.reg_center_type.cr_dtimes IS 'Created DateTimestamp : Date and Timestamp when the record is created/inserted';
-- ddl-end --
COMMENT ON COLUMN master.reg_center_type.upd_by IS 'Updated By : ID or name of the user who update the record with new values';
-- ddl-end --
COMMENT ON COLUMN master.reg_center_type.upd_dtimes IS 'Updated DateTimestamp : Date and Timestamp when any of the fields in the record is updated with new values.';
-- ddl-end --
COMMENT ON COLUMN master.reg_center_type.is_deleted IS 'IS_Deleted : Flag to mark whether the record is Soft deleted.';
-- ddl-end --
COMMENT ON COLUMN master.reg_center_type.del_dtimes IS 'Deleted DateTimestamp : Date and Timestamp when the record is soft deleted with is_deleted=TRUE';
-- ddl-end --
