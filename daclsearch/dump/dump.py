import os
import json
import logging
from InquirerPy import inquirer
from daclsearch.dump.ldap import LdapUtils
from daclsearch.dump.db import ldap_dict_to_db


class DACLSearchDump:
    """
    Handles LDAP dump and populates the SQLite database.
    Optionally exports to JSON if specified.
    """

    def __init__(self, ldap_args, db_path="daclsearch.sqlite", json_path=None, input_path=None):
        self.ldap_args = ldap_args
        self.db_path = db_path
        self.json_path = json_path
        self.input_path = input_path

    def run(self, full=False):
        # Check if DB exists and ask for overwrite
        folder = os.path.dirname(os.path.abspath(self.db_path))
        if not os.path.exists(folder):
            logging.error(f"Database folder '{folder}' does not exist.")
            return
        elif os.path.exists(self.db_path):
            overwrite = inquirer.confirm(
                message=f"Database '{self.db_path}' already exists. Overwrite ?", mandatory=True, default=False
            ).execute()

            if overwrite:
                os.remove(self.db_path)
            else:
                logging.info("Aborted: Database not overwritten.")
                return

        if self.input_path:
            # Load LDAP data from input file
            if not os.path.exists(self.input_path):
                logging.info(f"File {self.input_path} does not exist")
                return

            with open(self.input_path, "r") as f:
                ldap_data = json.load(f)
        else:
            # Dump data from LDAP
            ldap_utils = LdapUtils(**self.ldap_args)
            ldap_data = ldap_utils.dump(full)

            # Optionally export to JSON
            if self.json_path:
                with open(self.json_path, "w") as f:
                    json.dump(ldap_data, f)
                logging.info(f"LDAP dump to JSON completed: {self.json_path}")

        # Populate SQLite DB directly from dict
        ldap_dict_to_db(ldap_data, db_path=self.db_path)
        logging.info(f"Database population completed: {self.db_path}")
