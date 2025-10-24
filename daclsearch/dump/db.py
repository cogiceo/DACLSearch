import sqlite3
import logging
from base64 import b64decode
from impacket.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.guid import GUID
from daclsearch.utils import ACE_TYPE


def init_db(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # ad_object table (add owner column)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS ad_object (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dn TEXT UNIQUE NOT NULL,
            name TEXT,
            sid TEXT,
            owner_id INTEGER
        )
    """
    )
    # ad_objectclass table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS ad_objectclass (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """
    )
    # ad_object_objectclass join table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS ad_object_objectclass (
            obj_id INTEGER NOT NULL,
            class_id INTEGER NOT NULL,
            PRIMARY KEY (obj_id, class_id),
            FOREIGN KEY (obj_id) REFERENCES ad_object(id) ON DELETE CASCADE,
            FOREIGN KEY (class_id) REFERENCES ad_objectclass(id) ON DELETE RESTRICT
        )
    """
    )
    # memberships table: principal_id (object id), group_id (object id)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS memberships (
            principal_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            PRIMARY KEY (principal_id, group_id),
            FOREIGN KEY (principal_id) REFERENCES ad_object(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES ad_object(id) ON DELETE RESTRICT
        )
    """
    )
    # ace_type table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS ace_type (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """
    )
    # object_type table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS object_type (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """
    )
    # aces table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS aces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_id INTEGER NOT NULL,
            principal_id INTEGER NOT NULL,
            type_id INTEGER NOT NULL,
            mask INTEGER NOT NULL,
            flags INTEGER,
            object_type_id INTEGER,
            inherited_object_type_id INTEGER,
            FOREIGN KEY (object_id) REFERENCES ad_object(id) ON DELETE CASCADE,
            FOREIGN KEY (principal_id) REFERENCES ad_object(id) ON DELETE CASCADE,
            FOREIGN KEY (type_id) REFERENCES ace_type(id) ON DELETE RESTRICT,
            FOREIGN KEY (object_type_id) REFERENCES object_type(id) ON DELETE RESTRICT,
            FOREIGN KEY (inherited_object_type_id) REFERENCES object_type(id) ON DELETE RESTRICT
        )
    """
    )
    conn.commit()
    return conn


def alias_check(alias, sid1, sid2):
    if alias.get(sid1) == sid2 or alias.get(sid2) == sid1:
        return True
    return False


def ldap_dict_to_db(ldap_dict, db_path="daclsearch.sqlite"):
    conn = init_db(db_path)
    c = conn.cursor()

    domain_sids = []
    for obj in ldap_dict["Domain-DNS"]["objects"]:
        if obj.get("objectSid"):
            domain_sids.append(obj.get("objectSid"))

    if not domain_sids:
        logging.error("Domain SID not found in LDAP data.")
        return

    # Helper caches for fast lookup
    object_dn_to_id = {}
    objectclass_name_to_id = {}
    ace_type_name_to_id = {}
    object_type_name_to_id = {}
    object_sid_to_id = {}

    # Insert object classes first and guid resolution
    obj_type_map = {}
    objectclass_names = set()
    object_type_names = set()
    for obj_data in ldap_dict.values():
        if "schemaIDGUID" in obj_data.get("attributes", []) or "rightsGuid" in obj_data.get("attributes", []):
            for obj in obj_data.get("objects", []):
                for attrib in ["schemaIDGUID", "rightsGuid"]:
                    if attrib in obj:
                        guid = GUID.from_bytes(b64decode(obj.get(attrib)))
                        obj_type_map[str(guid).lower()] = obj["name"]

    # Fallback to impacket GUID mapping if not found
    impacket_guids = SCHEMA_OBJECTS | EXTENDED_RIGHTS
    for guid in impacket_guids.keys():
        if guid not in obj_type_map:
            obj_type_map[guid] = impacket_guids[guid]

    for obj_data in ldap_dict.values():
        for obj in obj_data.get("objects", []):
            # Collect object classes
            for oc in obj.get("objectClass", []):
                objectclass_names.add(oc)

            # Collect object types from nTSecurityDescriptor
            nt_sd = obj.get("nTSecurityDescriptor")
            gmsa_sd = obj.get("msDS-GroupMSAMembership")
            for b64_sd in [nt_sd, gmsa_sd]:
                if b64_sd:
                    sd = SECURITY_DESCRIPTOR().from_bytes(b64decode(b64_sd))
                    for ace in sd.Dacl.aces:
                        # Use resolved name GUID to get object type names
                        if hasattr(ace, "ObjectType") and ace.ObjectType:
                            guid = str(ace.ObjectType).lower()
                            obj_type_name = obj_type_map.get(guid, guid)
                            object_type_names.add(obj_type_name)
                        if hasattr(ace, "InheritedObjectType") and ace.InheritedObjectType:
                            guid = str(ace.InheritedObjectType).lower()
                            obj_type_name = obj_type_map.get(guid, guid)
                            object_type_names.add(obj_type_name)

    # Insert object classes
    for oc_name in objectclass_names:
        c.execute("INSERT OR IGNORE INTO ad_objectclass (name) VALUES (?)", (oc_name,))
        c.execute("SELECT id FROM ad_objectclass WHERE name=?", (oc_name,))
        objectclass_name_to_id[oc_name] = c.fetchone()[0]

    # Insert ACE types from utils
    for ace_type_name in ACE_TYPE.values():
        c.execute("INSERT OR IGNORE INTO ace_type (name) VALUES (?)", (ace_type_name,))
        c.execute("SELECT id FROM ace_type WHERE name=?", (ace_type_name,))
        ace_type_name_to_id[ace_type_name] = c.fetchone()[0]

    # Insert object types
    for obj_type_name in object_type_names:
        c.execute("INSERT OR IGNORE INTO object_type (name) VALUES (?)", (obj_type_name,))
        c.execute("SELECT id FROM object_type WHERE name=?", (obj_type_name,))
        object_type_name_to_id[obj_type_name] = c.fetchone()[0]

    special_grp_map = {}
    for obj in ldap_dict["Foreign-Security-Principal"]["objects"]:
        if not obj.get("name").startswith("S-1-"):
            obj_sid = obj.get("objectSid")
            special_grp_map[obj_sid] = obj["name"]

    # Populate ad_object table and ad_object_objectclass
    for obj_data in ldap_dict.values():
        for obj in obj_data.get("objects", []):
            dn = obj.get("distinguishedName")
            sid = obj.get("objectSid", None)
            name = obj.get("sAMAccountName") or obj.get("name")
            if sid and name.startswith("S-1-"):
                name = special_grp_map.get(sid, name)
            if name in special_grp_map:
                continue

            c.execute(
                "INSERT OR IGNORE INTO ad_object (dn, name, sid, owner_id) VALUES (?, ?, ?, ?)", (dn, name, sid, None)
            )
            c.execute("SELECT id FROM ad_object WHERE dn=?", (dn,))
            obj_id = c.fetchone()[0]
            object_dn_to_id[dn] = obj_id
            object_sid_to_id[sid] = obj_id

            # Track user/computer objects for default group membership
            object_classes = obj.get("objectClass", [])
            for oc in object_classes:
                class_id = objectclass_name_to_id[oc]
                c.execute(
                    "INSERT OR IGNORE INTO ad_object_objectclass (obj_id, class_id) VALUES (?, ?)", (obj_id, class_id)
                )

    authenticated_users_id = object_sid_to_id.get("S-1-5-11")

    for domain_sid in domain_sids:
        global_groups = [
            f"{domain_sid}-512",
            f"{domain_sid}-513",
            f"{domain_sid}-515",
            f"{domain_sid}-516",
        ]

        # Authenticated Users is member of Domain Users/Domain Computers/Domain Controllers/Domain Admins
        for sid in global_groups:
            glb_id = object_sid_to_id.get(sid)
            if glb_id:
                c.execute(
                    "INSERT OR IGNORE INTO memberships (principal_id, group_id) VALUES (?, ?)",
                    (glb_id, authenticated_users_id),
                )

    special_groups_sid = [
        "S-1-18-6",
        "S-1-18-1",
        "S-1-5-64-21",
        "S-1-1-0",
        "S-1-18-3",
        "S-1-18-4",
        "S-1-18-5",
        "S-1-5-2",
        "S-1-5-64-10",
        "S-1-5-1000",
        "S-1-5-64-14",
        "S-1-5-15",
    ]

    placeholder_sid = ["S-1-3-1", "S-1-3-0"]

    # Authenticated Users is member of all special groups above
    for sid in special_groups_sid:
        sg_id = object_sid_to_id.get(sid)
        if sg_id:
            c.execute(
                "INSERT OR IGNORE INTO memberships (principal_id, group_id) VALUES (?, ?)",
                (authenticated_users_id, sg_id),
            )

    for obj_data in ldap_dict.values():
        for obj in obj_data.get("objects", []):

            dn = obj.get("distinguishedName")
            obj_id = object_dn_to_id.get(dn)
            nt_sd = obj.get("nTSecurityDescriptor")
            gmsa_sd = obj.get("msDS-GroupMSAMembership")

            # Insert memberships for each principals
            if "sAMAccountName" in obj_data.get("attributes", []):
                member_of = obj.get("memberOf", [])
                if isinstance(member_of, str):
                    member_of = [member_of]

                primary_group_id = obj.get("primaryGroupID")
                for group_dn in member_of:
                    group_id = object_dn_to_id.get(group_dn)
                    if obj_id and group_id:
                        c.execute(
                            "INSERT OR IGNORE INTO memberships (principal_id, group_id) VALUES (?, ?)",
                            (obj_id, group_id),
                        )
                if primary_group_id:
                    obj_domain_sid = obj.get("objectSid").rsplit("-", 1)[0]
                    primary_group_sid = f"{obj_domain_sid}-{primary_group_id}"
                    pg_id = object_sid_to_id.get(primary_group_sid)
                    c.execute(
                        "INSERT OR IGNORE INTO memberships (principal_id, group_id) VALUES (?, ?)", (obj_id, pg_id)
                    )

            for b64_sd in [nt_sd, gmsa_sd]:
                if b64_sd and obj_id:

                    # Set object owner
                    sd = SECURITY_DESCRIPTOR().from_bytes(b64decode(b64_sd))
                    owner_sid = str(sd.Owner)

                    if owner_sid:
                        owner_id = object_sid_to_id.get(owner_sid)
                        if owner_id:
                            c.execute("UPDATE ad_object SET owner_id=? WHERE dn=?", (owner_id, dn))

                    # Insert ACEs
                    for ace in sd.Dacl.aces:

                        principal_sid = str(ace.Sid)
                        if principal_sid in placeholder_sid:
                            continue
                        if principal_sid == "S-1-5-10":
                            principal_id = obj_id
                        else:
                            principal_id = object_sid_to_id.get(principal_sid)
                            if not principal_id:
                                logging.debug(f"Principal SID {principal_sid} not found in object SID mapping.")
                                # Insert object with class 'user' if not mapped
                                c.execute(
                                    "INSERT OR IGNORE INTO ad_object (dn, name, sid, owner_id) VALUES (?, ?, ?, ?)",
                                    (f"UNKNOWN={principal_sid}", principal_sid, principal_sid, None),
                                )
                                c.execute("SELECT id FROM ad_object WHERE sid=?", (principal_sid,))
                                result = c.fetchone()
                                if not result:
                                    logging.debug(f"Failed to insert principal SID {principal_sid} into ad_object.")
                                    continue
                                new_obj_id = result[0]
                                c.execute("SELECT id FROM ad_objectclass WHERE name=?", ("user",))
                                user_class_id = c.fetchone()[0]
                                c.execute(
                                    "INSERT OR IGNORE INTO ad_object_objectclass (obj_id, class_id) VALUES (?, ?)",
                                    (new_obj_id, user_class_id),
                                )
                                object_sid_to_id[principal_sid] = new_obj_id
                                principal_id = new_obj_id

                        ace_type_name = ACE_TYPE[str(ace.AceType).replace("ACEType.", "")]
                        type_id = ace_type_name_to_id.get(ace_type_name)

                        mask = int(ace.Mask)
                        flags = int(ace.AceFlags)
                        if not flags:
                            flags = None

                        # Resolve GUID name
                        object_type_id = None
                        if hasattr(ace, "ObjectType") and ace.ObjectType:
                            guid = str(ace.ObjectType).lower()
                            obj_type_name = obj_type_map.get(guid, guid)
                            object_type_id = object_type_name_to_id.get(obj_type_name)
                        elif gmsa_sd == b64_sd:
                            # The ms-DS-GroupMSAMembership SD is linked to the ms-DS-ManagedPassword attribut
                            guid = "e362ed86-b728-0842-b27d-2dea7a9df218"
                            obj_type_name = obj_type_map.get(guid, guid)
                            object_type_id = object_type_name_to_id.get(obj_type_name)

                        inherited_object_type_id = None
                        if hasattr(ace, "InheritedObjectType") and ace.InheritedObjectType:
                            guid = str(ace.InheritedObjectType).lower()
                            inh_obj_type_name = obj_type_map.get(guid, guid)
                            inherited_object_type_id = object_type_name_to_id.get(inh_obj_type_name)

                        c.execute(
                            """
                            INSERT INTO aces (
                                object_id, principal_id, type_id, mask, flags, object_type_id, inherited_object_type_id
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (obj_id, principal_id, type_id, mask, flags, object_type_id, inherited_object_type_id),
                        )

    conn.commit()
    conn.close()
