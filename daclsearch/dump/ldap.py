import sys
import base64
import logging
from rich.live import Live
from rich.spinner import Spinner
from rich.console import Console
from winacl.dtyp.sid import SID
from impacket.ldap.ldap import LDAPConnection, LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry, SDFlagsControl, SimplePagedResultsControl, Control


class LdapUtils:

    def __init__(
        self, dc_ip, dc_host, domain, logon_domain, username, password, hashes, do_kerberos, aeskey, use_ldaps, use_gc
    ):
        self.__kdc_ip = dc_ip
        self.__kdc_host = dc_host
        self.__username = username
        self.__domain = domain
        self.__logon_domain = logon_domain if logon_domain else self.__domain
        self.__password = password if password else ""
        self.__lmhash = ""
        self.__nthash = ""
        self.__do_kerberos = do_kerberos
        self.__aeskey = aeskey
        self.__ldaps_flag = use_ldaps
        self.__gc_flag = use_gc

        if hashes:
            self.__lmhash, self.__nthash = hashes.split(":")

        # OID to query deleted objects
        self.show_recycled_control = Control()
        self.show_recycled_control["controlType"] = "1.2.840.113556.1.4.2064"
        self.show_recycled_control["criticality"] = True

        # Phantom Root control using SDFlagsControl structure
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/782fa852-2aef-42cd-b3d7-3f7a85861289
        self.phantom_root_control = SDFlagsControl(False, 0x00000002)
        self.phantom_root_control["controlType"] = "1.2.840.113556.1.4.1340"

        base_dn = ",".join(f"DC={part}" for part in domain.split("."))
        forest_root_dn = ",".join(f"DC={part}" for part in domain.split(".")[-2:])

        # Naming Contexts
        self.search_dn = [
            "",
            f"CN=Deleted Objects,{base_dn}",
        ]
        # Application Naming Contexts
        if not self.__gc_flag:
            self.search_dn.append(f"DC=DomainDnsZones,{base_dn}")
            self.search_dn.append(f"DC=ForestDnsZones,{forest_root_dn}")

        # Attributes to encode in base64
        self.force_b64 = ["objectGUID", "rightsGuid", "schemaIDGUID"]

        self.console = Console()

    def get_ldap_connection(self, base_dn):
        """
        Establishes and returns a connection to the LDAP server.
        """

        if self.__ldaps_flag:
            prefix = "ldaps://"
        elif self.__gc_flag:
            prefix = "gc://"
        else:
            prefix = "ldap://"

        if self.__kdc_host:
            ldap_url = f"{prefix}{self.__kdc_host}"
        else:
            ldap_url = f"{prefix}{self.__kdc_ip}"

        ldap_conn = LDAPConnection(ldap_url, self.__kdc_ip)
        ldap_conn.searchBase = base_dn

        # Authentication
        if self.__do_kerberos:
            ldap_conn.kerberosLogin(
                self.__username,
                self.__password,
                self.__logon_domain,
                self.__lmhash,
                self.__nthash,
                self.__aeskey,
                kdcHost=self.__kdc_ip,
            )
        else:
            ldap_conn.login(self.__username, self.__password, self.__logon_domain, self.__lmhash, self.__nthash)
        return ldap_conn

    def dump(self, full):
        """
        Dumps objects from the LDAP directory
        """

        # Attributes to dump
        if full:
            attributes = ["*"]
        else:
            attributes = [
                "distinguishedName",
                "sAMAccountName",
                "name",
                "objectSid",
                "memberOf",
                "nTSecurityDescriptor",
                "defaultSecurityDescriptor",
                "msDS-GroupMSAMembership",
                "objectCategory",
                "objectClass",
                "primaryGroupID",
                "schemaIDGUID",
                "rightsGuid",
                "lDAPDisplayName",
            ]

        # Itterates over search DN
        entries = {}
        for dn in self.search_dn:
            ldap_connection = self.get_ldap_connection(dn)
            entries = self.dump_context(entries, ldap_connection, dn, attributes)

        for key, value in entries.items():
            entries[key]["attributes"] = sorted(list(value["attributes"]))
        return entries

    def dump_context(self, entries, ldap_conn, search_dn, attributes_filter=None):
        """
        Dumps all LDAP objects under the specified base distinguished name
        """
        searchControls = []
        searchControls.append(SDFlagsControl())
        searchControls.append(SimplePagedResultsControl(size=500))

        if search_dn == "":
            logging.info(
                "Querying all naming context replicas except the application naming contexts (this may take a while):"
            )
            searchControls.append(self.phantom_root_control)
        elif search_dn.startswith("CN=Deleted Objects"):
            logging.info("Querying deleted and recycled objects (requires Domain Admin privileges by default):")
            searchControls.append(self.show_recycled_control)
        else:
            logging.info(f"Querying the {search_dn} application naming context:")

        spinner = Spinner("line", text="Querying objects...")
        with Live(spinner, refresh_per_second=10, console=self.console, transient=True):
            processed_count = 0
            try:
                # LDAP query
                result = ldap_conn.search(
                    searchBase=search_dn,
                    attributes=attributes_filter,
                    searchControls=searchControls,
                )

                # Parse LDAP objects
                for raw_entry in result:

                    if isinstance(raw_entry, SearchResultEntry):
                        entry = {}
                        attributes = []

                        for attr in raw_entry["attributes"]:
                            attr_type = str(attr["type"])
                            attributes.append(attr_type)
                            values = []

                            for value in attr["vals"]:
                                if attr_type in self.force_b64:
                                    values.append(base64.b64encode(bytes(value)).decode())
                                else:
                                    decoded_value = bytes(value).decode(errors="ignore")
                                    if decoded_value.isprintable():
                                        values.append(decoded_value)
                                    else:
                                        values.append(base64.b64encode(bytes(value)).decode())

                            if attr_type == "objectSid":
                                sid = str(SID().from_bytes(base64.b64decode(values[0])))
                                entry[attr_type] = sid
                            else:
                                entry[attr_type] = values if len(values) > 1 else values[0]  # flatten if single value

                        object_category = None
                        if "nTSecurityDescriptor" in entry:
                            if entry and "objectCategory" in entry:
                                object_category = entry["objectCategory"].split(",")[0].split("=")[1]
                            elif search_dn.startswith("CN=Deleted Objects") and entry.get(
                                "distinguishedName", ""
                            ).endswith(search_dn):
                                object_category = "Deleted-Objects"

                        if object_category and not entry in entries.get(object_category, {}).get("objects", []):

                            entries.setdefault(object_category, {}).setdefault("attributes", set()).update(
                                set(attributes)
                            )
                            entries.setdefault(object_category, {}).setdefault("objects", []).append(entry)
                            processed_count += 1

                self.console.print(f"[white]- Found {processed_count} objects[/white]")

            except LDAPSearchError as e:
                if search_dn == "":
                    logging.error(f"Failed to perform search on base DN '{search_dn}': {e}")
                    sys.exit()
                logging.error(f"Search failed on {search_dn}: {e}")
        return entries
