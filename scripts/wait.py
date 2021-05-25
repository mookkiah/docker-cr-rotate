import logging
import logging.config
import os
import sys

from pygluu.containerlib import get_manager
from pygluu.containerlib import wait_for
from pygluu.containerlib.validators import validate_persistence_type
from pygluu.containerlib.validators import validate_persistence_ldap_mapping
from pygluu.containerlib.validators import validate_persistence_sql_dialect

from settings import LOGGING_CONFIG

CONTAINER_META_OPTS = ("docker", "kubernetes")

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("wait")


def main():
    persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
    validate_persistence_type(persistence_type)

    ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")
    validate_persistence_ldap_mapping(persistence_type, ldap_mapping)

    if persistence_type == "sql":
        sql_dialect = os.environ.get("GLUU_SQL_DB_DIALECT", "mysql")
        validate_persistence_sql_dialect(sql_dialect)

    meta = os.environ.get("GLUU_CONTAINER_METADATA")
    if meta not in CONTAINER_META_OPTS:
        logger.error(
            "Invalid value for GLUU_CONTAINER_METADATA environment variable; "
            "please choose one of {}".format(", ".join(CONTAINER_META_OPTS)))
        sys.exit(1)

    manager = get_manager()
    deps = ["config", "secret"]

    if persistence_type == "hybrid":
        deps += ["ldap", "couchbase"]
    else:
        deps.append(persistence_type)
    wait_for(manager, deps)


if __name__ == "__main__":
    main()
