\c mosip_master 

GRANT CONNECT
   ON DATABASE mosip_master
   TO masteruser;

GRANT USAGE
   ON SCHEMA master
   TO masteruser;

GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES
   ON ALL TABLES IN SCHEMA master
   TO masteruser;

ALTER DEFAULT PRIVILEGES IN SCHEMA master 
	GRANT SELECT,INSERT,UPDATE,DELETE,REFERENCES ON TABLES TO masteruser;

