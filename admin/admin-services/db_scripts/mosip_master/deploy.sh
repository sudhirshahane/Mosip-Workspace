
# SU_USER_PWD ='postgres'
# SU_USER='postgres'
# DB_SERVERIP='localhost'
# DB_PORT='5432'
# DEFAULT_DB_NAME='mosip_master'


## Properties file
set -e
properties_file="$1"
echo `date "+%m/%d/%Y %H:%M:%S"` ": $properties_file"
if [ -f "$properties_file" ]
then
     echo `date "+%m/%d/%Y %H:%M:%S"` ": Property file \"$properties_file\" found."
    while IFS='=' read -r key value
    do
        key=$(echo $key | tr '.' '_')
         eval ${key}=\${value}
    done < "$properties_file"
else
     echo `date "+%m/%d/%Y %H:%M:%S"` ": Property file not found, Pass property file name as argument."
fi

## Terminate existing connections
echo "Terminating active connections" 
CONN=$(PGPASSWORD=$SU_USER_PWD psql --username=$SU_USER --host=$DB_SERVERIP --port=$DB_PORT --dbname=$DEFAULT_DB_NAME -t -c "SELECT count(pg_terminate_backend(pg_stat_activity.pid)) FROM pg_stat_activity WHERE datname = '$MOSIP_DB_NAME' AND pid <> pg_backend_pid()";exit;)
echo "Terminated connections"

## Drop db and role
PGPASSWORD=$SU_USER_PWD psql --username=$SU_USER --host=$DB_SERVERIP --port=$DB_PORT --dbname=$DEFAULT_DB_NAME -f drop_db.sql
PGPASSWORD=$SU_USER_PWD psql --username=$SU_USER --host=$DB_SERVERIP --port=$DB_PORT --dbname=$DEFAULT_DB_NAME -f drop_role.sql

## Create users
echo `date "+%m/%d/%Y %H:%M:%S"` ": Creating database users" | tee
PGPASSWORD=$SU_USER_PWD psql --username=$SU_USER --host=$DB_SERVERIP --port=$DB_PORT --dbname=$DEFAULT_DB_NAME -f role_dbuser.sql -v dbuserpwd=\'$DBUSER_PWD\'

## Create DB
PGPASSWORD=$SU_USER_PWD psql --username=$SU_USER --host=$DB_SERVERIP --port=$DB_PORT --dbname=$DEFAULT_DB_NAME -f db.sql 
PGPASSWORD=$SU_USER_PWD psql --username=$SU_USER --host=$DB_SERVERIP --port=$DB_PORT --dbname=$DEFAULT_DB_NAME -f ddl.sql

## Grants
PGPASSWORD=$SU_USER_PWD psql --username=$SU_USER --host=$DB_SERVERIP --port=$DB_PORT --dbname=$DEFAULT_DB_NAME -f grants.sql

echo `date "+%m/%d/%Y %H:%M:%S"` ": Deploying DML for ${MOSIP_DB_NAME} database" 
PGPASSWORD=$SU_USER_PWD psql --username=$SU_USER --host=$DB_SERVERIP --port=$DB_PORT --dbname=$DEFAULT_DB_NAME -a -b -f dml.sql 

## Populate tables
if [ ${DML_FLAG} == 1 ]
then
    echo `date "+%m/%d/%Y %H:%M:%S"` ": Deploying DML for ${MOSIP_DB_NAME} database" 
    PGPASSWORD=$SU_USER_PWD psql --username=$SU_USER --host=$DB_SERVERIP --port=$DB_PORT --dbname=$DEFAULT_DB_NAME -a -b -f dml.sql 
fi

