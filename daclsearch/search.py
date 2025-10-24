import sqlite3
import json
from winacl.dtyp.ace import ADS_ACCESS_MASK, AceFlags
from daclsearch.utils import MASK, MASK_INV, ACE_FLAG, ACE_FLAG_INV


class DACLSearch:
    def __init__(self, db_path="daclsearch.sqlite"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.obj_filters = self.get_object_filters()
        self.all_objects = self.get_all_objects()

    def get_all_objects(self):
        results = {"name": [], "dn": [], "sid": []}
        c = self.conn.cursor()
        c.execute(
            """
            SELECT DISTINCT dn, name, sid
            FROM ad_object
        """
        )
        for row in c.fetchall():
            if not row["dn"].startswith("UNKNOWN="):
                results["dn"].append(row["dn"])
            if row["sid"]:
                results["name"].append(row["name"])
                results["sid"].append(row["sid"])
        results["name"] = sorted(results["name"])
        results["dn"] = sorted(results["dn"], key=lambda dn: dn.count(","))
        results["sid"] = sorted(results["sid"])
        return results

    def get_object_filters(self):
        filters = {}
        c = self.conn.cursor()

        # Principals: only those present in ad_object with objectClass 'user' or 'group'
        c.execute(
            """
            SELECT DISTINCT ao.name
            FROM ad_object ao
            JOIN ad_object_objectclass apoc ON ao.id = apoc.obj_id
            JOIN ad_objectclass oc ON apoc.class_id = oc.id
            WHERE ao.sid IS NOT NULL
            AND (oc.name = 'user' OR oc.name = 'group' OR oc.name = 'foreignSecurityPrincipal')
            AND ao.name != 'Self' 
            """
        )
        filters["principal_names"] = sorted([row["name"] for row in c.fetchall()])

        # ACE Types present in aces
        c.execute(
            """
            SELECT DISTINCT at.name
            FROM aces
            JOIN ace_type at ON aces.type_id = at.id
            """
        )
        filters["ace_types"] = sorted([row["name"] for row in c.fetchall()])

        # Access Masks present in aces
        c.execute("SELECT DISTINCT mask FROM aces")
        masks = [row["mask"] for row in c.fetchall()]
        access_masks = set()
        for mask in masks:
            mask = ADS_ACCESS_MASK(mask).name
            rights = mask.split("|")
            for right in rights:
                if right in MASK_INV:
                    access_masks.add(MASK_INV[right])
        filters["access_masks"] = sorted(access_masks)

        # ACE Flags present in aces
        c.execute("SELECT DISTINCT flags FROM aces")
        flags = [row["flags"] for row in c.fetchall()]
        ace_flags = set()
        for flag in flags:
            if not flag:
                ace_flags.add("No value")
                continue
            flag = AceFlags(flag).name
            flag_list = flag.split("|")
            for flag_entry in flag_list:
                if flag_entry in ACE_FLAG_INV:
                    ace_flags.add(ACE_FLAG_INV[flag_entry])
        filters["ace_flags"] = sorted(ace_flags)

        # Object Types present in aces
        c.execute(
            """
            SELECT DISTINCT ot.name
            FROM aces
            LEFT JOIN object_type ot ON aces.object_type_id = ot.id
        """
        )
        filters["object_types"] = []
        for row in c.fetchall():
            if row["name"]:
                filters["object_types"].append(row["name"])
            else:
                filters["object_types"].append("No value")

        # Inherited Object Types present in aces
        c.execute(
            """
            SELECT DISTINCT iot.name
            FROM aces
            LEFT JOIN object_type iot ON aces.inherited_object_type_id = iot.id
        """
        )
        filters["inherited_object_types"] = []
        for row in c.fetchall():
            if row["name"]:
                filters["inherited_object_types"].append(row["name"])
            else:
                filters["inherited_object_types"].append("No value")

        # Owners: only those present in aces
        c.execute(
            """
            SELECT DISTINCT ao.name
            FROM aces
            JOIN ad_object ao ON aces.object_id = ao.id
            WHERE ao.name IS NOT NULL
        """
        )
        filters["owner_names"] = sorted([row["name"] for row in c.fetchall()])

        # Object DNs present in aces
        c.execute(
            """
            SELECT DISTINCT ao.dn
            FROM aces
            JOIN ad_object ao ON aces.object_id = ao.id
        """
        )
        filters["target_object_dns"] = sorted([row["dn"] for row in c.fetchall() if row["dn"] is not None])

        # Object Classes present in aces
        c.execute(
            """
            SELECT DISTINCT oc.name
            FROM aces
            JOIN ad_object ao ON aces.object_id = ao.id
            JOIN ad_object_objectclass aoc ON ao.id = aoc.obj_id
            JOIN ad_objectclass oc ON aoc.class_id = oc.id
        """
        )
        filters["target_object_classes"] = sorted([row["name"] for row in c.fetchall()])

        # Principal Object Classes present in aces
        c.execute(
            """
            SELECT DISTINCT poc.name
            FROM aces
            JOIN ad_object ap ON aces.principal_id = ap.id
            JOIN ad_object_objectclass apoc ON ap.id = apoc.obj_id
            JOIN ad_objectclass poc ON apoc.class_id = poc.id
            WHERE ap.sid IS NOT NULL
            AND ap.name NOT LIKE "S-1-%"
            """
        )
        filters["principal_object_classes"] = sorted([row["name"] for row in c.fetchall()])
        return filters

    def get_memberships(self, principal_names):
        """
        Returns a mapping: { principal_name: [groups...] }
        for all principals in principal_names, including recursive groups.
        """
        c = self.conn.cursor()

        query = """
        WITH RECURSIVE group_hierarchy(principal, group_name) AS (
            -- Start with direct memberships
            SELECT u.name AS principal, g.name AS group_name
            FROM memberships m
            JOIN ad_object u ON m.principal_id = u.id
            JOIN ad_object g ON m.group_id = g.id
            WHERE u.name IN (SELECT value FROM json_each(:principal_names))

            UNION

            -- Add recursive memberships
            SELECT gh.principal, g2.name
            FROM group_hierarchy gh
            JOIN ad_object g1 ON gh.group_name = g1.name
            JOIN memberships m2 ON m2.principal_id = g1.id
            JOIN ad_object g2 ON m2.group_id = g2.id
        )
        SELECT DISTINCT principal, group_name
        FROM group_hierarchy
        ORDER BY principal, group_name;
        """

        params = {"principal_names": json.dumps(list(principal_names))}
        c.execute(query, params)

        results = {}
        all_groups = set()

        for row in c.fetchall():
            principal = row["principal"]
            group = row["group_name"]

            results.setdefault(principal, []).append(group)
            all_groups.add(group)

        return results, sorted(all_groups)

    def search(self, filters):
        memberships = {}
        ownerships = {}
        obj_rights = {}

        recursivity_enabled = filters.get("recursive_search", True)
        ownership_enabled = filters.get("ownership_search", True)
        filters["include_self_rights"] = filters.get("include_self_rights", True)

        # Principals
        if not filters.get("include_principal_names"):
            search_principals = set(self.obj_filters["principal_names"])
            if filters.get("exclude_principal_names"):
                search_principals -= set(filters["exclude_principal_names"])
        else:
            search_principals = set(filters["include_principal_names"])

        all_principals_class = self.get_principal_class()

        all_principals_groups, all_groups = self.get_memberships(search_principals)
        all_principals = set(search_principals)
        all_principals.update(all_groups)

        if ownership_enabled:
            owners = self.get_own_objects(filters)
            if owners:
                for owner in owners:
                    owner = dict(owner)
                    ownerships.setdefault(owner["owner_name"], []).append(owner["dn"])

        # Get ACEs for the specified filters
        aces = self.get_aces(filters)
        if aces:
            for ace in aces:
                obj_rights.setdefault(ace["principal_name"], {}).setdefault(ace["object_dn"], []).append(
                    self.ace_row_to_dict(ace)
                )
            if recursivity_enabled:
                for principal in obj_rights:
                    if principal not in memberships:
                        memberships[principal] = list(all_principals_groups.get(principal, set()))

        result_principals = {}
        for principal in search_principals:
            if principal in obj_rights or principal in ownerships and principal in search_principals:
                result_principals.setdefault(all_principals_class.get(principal), []).append(principal)
            elif recursivity_enabled:
                for group in all_principals_groups.get(principal, set()):
                    if group in obj_rights or group in ownerships:
                        result_principals.setdefault(all_principals_class.get(principal), []).append(principal)
                        if principal not in memberships:
                            memberships[principal] = list(all_principals_groups.get(principal, set()))
                        break
        if result_principals:
            return {
                "result_principals": result_principals,
                "obj_rights": obj_rights,
                "memberships": memberships,
                "ownerships": ownerships,
                "ownership_search": ownership_enabled,
            }
        return None

    def get_object_ace(self, column, value):
        sql_params = {"col_name": f"{column}_col", "value": value}
        c = self.conn.cursor()
        query = """
            SELECT DISTINCT aces.id,
                ao.dn as object_dn,
                ao.name as object_name,
                ap.dn as principal_dn,
                ap.name as principal_name,
                ap.sid as principal_sid,
                at.name as ace_type,
                aces.mask as mask,
                aces.flags as flags,
                ot.name as object_type,
                iot.name as inherited_object_type
            FROM aces
            -- Joins to get object and principal details
            JOIN ad_object ao ON aces.object_id = ao.id
            JOIN ad_object ap ON aces.principal_id = ap.id
            JOIN ace_type at ON aces.type_id = at.id
            LEFT JOIN object_type ot ON aces.object_type_id = ot.id
            LEFT JOIN object_type iot ON aces.inherited_object_type_id = iot.id
            LEFT JOIN ad_object_objectclass aoc ON ao.id = aoc.obj_id
            LEFT JOIN ad_objectclass oc ON aoc.class_id = oc.id
            LEFT JOIN ad_object_objectclass apoc ON ap.id = apoc.obj_id
            LEFT JOIN ad_objectclass poc ON apoc.class_id = poc.id
            WHERE (CASE WHEN :col_name = 'name_col' THEN ao.name
                        WHEN :col_name = 'dn_col' THEN ao.dn
                        WHEN :col_name = 'sid_col' THEN ao.sid
                    END) = :value
        """
        c.execute(query, sql_params)
        tmp_aces = c.fetchall()
        aces = {}
        if tmp_aces:
            object_dn = tmp_aces[0]["object_dn"]
            for ace in tmp_aces:
                aces.setdefault(f'{ace["principal_name"]} ({ace["principal_sid"]})', []).append(
                    self.ace_row_to_dict(ace)
                )

        return object_dn, aces

    def get_principal_class(self):
        """
        Returns a dict {principal_name: object_class_name} where only the last link between object and class is kept.
        """

        c = self.conn.cursor()
        query = """
            SELECT ap.name AS principal_name, poc.name AS object_class_name
            FROM ad_object ap
            JOIN ad_object_objectclass apoc ON ap.id = apoc.obj_id
            JOIN ad_objectclass poc ON apoc.class_id = poc.id
            WHERE ap.sid IS NOT NULL
            AND apoc.rowid = (
                SELECT MAX(apoc2.rowid)
                FROM ad_object_objectclass apoc2
                WHERE apoc2.obj_id = ap.id
            )
        """
        c.execute(query)
        # Return as dict for easier lookup
        return {row["principal_name"]: row["object_class_name"] for row in c.fetchall()}

    def get_own_objects(self, filters):
        c = self.conn.cursor()
        # JSON encode for SQL
        sql_filters = {k: json.dumps(v) if v is not None else None for k, v in filters.items()}
        query = """
            SELECT DISTINCT ao.dn, own.name as owner_name
            FROM ad_object ao
            LEFT JOIN ad_object_objectclass apoc ON ao.id = apoc.obj_id
            LEFT JOIN ad_objectclass poc ON apoc.class_id = poc.id
            LEFT JOIN ad_object_objectclass aoc ON ao.id = aoc.obj_id
            LEFT JOIN ad_objectclass oc ON aoc.class_id = oc.id
            LEFT JOIN ad_object own ON ao.owner_id = own.id
            -- Principal Names
            WHERE (
                :include_principal_names IS NULL OR json_array_length(:include_principal_names) = 0
                OR ao.owner_id IN (
                    SELECT id FROM ad_object WHERE name IN (SELECT value FROM json_each(:include_principal_names))
                )
            )
            AND (
                :exclude_principal_names IS NULL OR json_array_length(:exclude_principal_names) = 0
                OR ao.owner_id NOT IN (
                    SELECT id FROM ad_object WHERE name IN (SELECT value FROM json_each(:exclude_principal_names))
                )
            )
            -- Principal Object Classes
            AND (
                :include_principal_object_classes IS NULL OR json_array_length(:include_principal_object_classes) = 0
                OR poc.name IN (SELECT value FROM json_each(:include_principal_object_classes))
            )
            AND (
                :exclude_principal_object_classes IS NULL OR json_array_length(:exclude_principal_object_classes) = 0
                OR poc.name NOT IN (SELECT value FROM json_each(:exclude_principal_object_classes))
            )
            -- Target Object DNs
            AND (
                :include_target_object_dns IS NULL OR json_array_length(:include_target_object_dns) = 0
                OR ao.dn IN (SELECT value FROM json_each(:include_target_object_dns))
            )
            AND (
                :exclude_target_object_dns IS NULL OR json_array_length(:exclude_target_object_dns) = 0
                OR ao.dn NOT IN (SELECT value FROM json_each(:exclude_target_object_dns))
            )
            -- Target Object Classes
            AND (
                :include_target_object_classes IS NULL OR json_array_length(:include_target_object_classes) = 0
                OR oc.name IN (SELECT value FROM json_each(:include_target_object_classes))
            )
            AND (
                :exclude_target_object_classes IS NULL OR json_array_length(:exclude_target_object_classes) = 0
                OR oc.name NOT IN (SELECT value FROM json_each(:exclude_target_object_classes))
            )
            -- Ownership Exclusion
            AND (
                :exclude_owner_names IS NULL OR json_array_length(:exclude_owner_names) = 0
                OR own.name NOT IN (SELECT value FROM json_each(:exclude_owner_names))
            )
        """

        c.execute(query, sql_filters)
        return c.fetchall()

    def ace_row_to_dict(self, ace):
        trustee = ace["object_name"] if ace["principal_name"] == "Self" else ace["principal_name"]

        ace_dict = {
            "Trustee": trustee,
            "Access Type": ace["ace_type"],
            "Access Mask": ace["mask"],
            "Object DN": ace["object_dn"],
            "Object Name": ace["object_name"],
            "Object Type": ace["object_type"],
            "Inherited Object Type": ace["inherited_object_type"],
        }

        if ace["flags"]:
            flags = AceFlags(ace["flags"]).name.split("|")
            ace_dict["Flags"] = sorted(
                (ACE_FLAG_INV.get(flag) for flag in flags if ACE_FLAG_INV.get(flag)), key=lambda s: s.lower()
            )

        return ace_dict

    def get_aces(self, filters):
        # Convert access_masks and ace_flags from text to int mask for SQL query
        def to_mask_int_list(values, map):
            result = []
            for v in values or []:
                if v == "No value":
                    result.append("No value")
                elif v in map:
                    if map is MASK:
                        # Convert to mask int using winacl constants if available
                        result.append(ADS_ACCESS_MASK[map[v]].value)
                    elif map is ACE_FLAG:
                        result.append(AceFlags[map[v]].value)
            return result

        # Prepare filters for SQL
        filters = dict(filters)
        # Convert access_masks and ace_flags

        for rule in ["include", "exclude"]:
            if f"{rule}_access_masks" in filters and filters[f"{rule}_access_masks"]:
                filters[f"{rule}_access_masks"] = to_mask_int_list(filters.get(f"{rule}_access_masks"), MASK)
            if f"{rule}_ace_flags" in filters and filters[f"{rule}_ace_flags"]:
                filters[f"{rule}_ace_flags"] = to_mask_int_list(filters.get(f"{rule}_ace_flags"), ACE_FLAG)

        # JSON encode for SQL
        filters = {k: json.dumps(v) if v is not None else None for k, v in filters.items()}

        query = """
            SELECT DISTINCT aces.id,
                ao.dn as object_dn,
                ao.name as object_name,
                ap.dn as principal_dn,
                ap.name as principal_name, 
                at.name as ace_type,
                aces.mask as mask,
                aces.flags as flags,
                ot.name as object_type,
                iot.name as inherited_object_type
            FROM aces
            
            -- Joins to get object and principal details
            JOIN ad_object ao ON aces.object_id = ao.id
            JOIN ad_object ap ON aces.principal_id = ap.id
            JOIN ace_type at ON aces.type_id = at.id
            LEFT JOIN object_type ot ON aces.object_type_id = ot.id
            LEFT JOIN object_type iot ON aces.inherited_object_type_id = iot.id
            LEFT JOIN ad_object_objectclass aoc ON ao.id = aoc.obj_id
            LEFT JOIN ad_objectclass oc ON aoc.class_id = oc.id
            LEFT JOIN ad_object_objectclass apoc ON ap.id = apoc.obj_id
            LEFT JOIN ad_objectclass poc ON apoc.class_id = poc.id
            
            -- Self Rights Inclusion
            WHERE
            (
                :include_self_rights = "true" OR (ao.id != ap.id)
            )
            -- Principal Names
            AND (
                :include_principal_names IS NULL OR json_array_length(:include_principal_names) = 0
                OR ap.name IN (SELECT value FROM json_each(:include_principal_names))
            )
            AND (
                :exclude_principal_names IS NULL OR json_array_length(:exclude_principal_names) = 0
                OR ap.name NOT IN (SELECT value FROM json_each(:exclude_principal_names))
            )
            -- Target Object DNs
            AND (
                :include_target_object_dns IS NULL OR json_array_length(:include_target_object_dns) = 0
                OR ao.dn IN (SELECT value FROM json_each(:include_target_object_dns))
            )
            AND (
                :exclude_target_object_dns IS NULL OR json_array_length(:exclude_target_object_dns) = 0
                OR ao.dn NOT IN (SELECT value FROM json_each(:exclude_target_object_dns))
            )
            -- Ace Types
            AND (
                :include_ace_types IS NULL OR json_array_length(:include_ace_types) = 0
                OR at.name IN (SELECT value FROM json_each(:include_ace_types))
            )
            AND (
                :exclude_ace_types IS NULL OR json_array_length(:exclude_ace_types) = 0
                OR at.name NOT IN (SELECT value FROM json_each(:exclude_ace_types))
            )
            -- Access Masks
            AND (
                :include_access_masks IS NULL OR json_array_length(:include_access_masks) = 0
                OR EXISTS (
                    SELECT 1 FROM json_each(:include_access_masks)
                    WHERE (aces.mask & CAST(value AS INTEGER)) = CAST(value AS INTEGER)
                )
            )
            AND (
                :exclude_access_masks IS NULL OR json_array_length(:exclude_access_masks) = 0
                OR NOT EXISTS (
                    SELECT 1 FROM json_each(:exclude_access_masks)
                    WHERE (aces.mask & CAST(value AS INTEGER)) = CAST(value AS INTEGER)
                )
            )
            -- ACE Flags
            AND (
                :include_ace_flags IS NULL OR json_array_length(:include_ace_flags) = 0
                OR EXISTS (
                    SELECT 1 FROM json_each(:include_ace_flags)
                    WHERE (value = 'No value' AND aces.flags IS NULL)
                    OR (value != 'No value' AND (aces.flags & CAST(value AS INTEGER)) = CAST(value AS INTEGER))
                )
            )
            AND (
                :exclude_ace_flags IS NULL OR json_array_length(:exclude_ace_flags) = 0
                OR NOT EXISTS (
                    SELECT 1 FROM json_each(:exclude_ace_flags)
                    WHERE (value = 'No value' AND aces.flags IS NULL)
                    OR (value != 'No value' AND (aces.flags & CAST(value AS INTEGER)) = CAST(value AS INTEGER))
                )
            )
            -- Object Types
            AND (
                :include_object_types IS NULL OR json_array_length(:include_object_types) = 0
                OR (SELECT 1 FROM json_each(:include_object_types) WHERE value = 'No value' AND ot.name IS NULL)
                OR (ot.name IN (SELECT value FROM json_each(:include_object_types)))
            )
            AND (
                :exclude_object_types IS NULL OR json_array_length(:exclude_object_types) = 0
                OR (SELECT 1 FROM json_each(:exclude_object_types) WHERE value = 'No value' AND ot.name IS NOT NULL)
                OR (ot.name NOT IN (SELECT value FROM json_each(:exclude_object_types)))
            )
            -- Inherited Object Types
            AND (
                :include_inherited_object_types IS NULL OR json_array_length(:include_inherited_object_types) = 0
                OR (SELECT 1 FROM json_each(:include_inherited_object_types) WHERE value = 'No value' AND iot.name IS NULL)
                OR (iot.name IN (SELECT value FROM json_each(:include_inherited_object_types)))
            )
            AND (
                :exclude_inherited_object_types IS NULL OR json_array_length(:exclude_inherited_object_types) = 0
                OR (SELECT 1 FROM json_each(:exclude_inherited_object_types) WHERE value = 'No value' AND iot.name IS NOT NULL)
                OR (iot.name NOT IN (SELECT value FROM json_each(:exclude_inherited_object_types)))
            )
            -- Target Object Classes
            AND (
                :include_target_object_classes IS NULL OR json_array_length(:include_target_object_classes) = 0
                OR oc.name IN (SELECT value FROM json_each(:include_target_object_classes))
            )
            AND (
                :exclude_target_object_classes IS NULL OR json_array_length(:exclude_target_object_classes) = 0
                OR oc.name NOT IN (SELECT value FROM json_each(:exclude_target_object_classes))
            )
            -- Principal Object Classes
            AND (
                :include_principal_object_classes IS NULL OR json_array_length(:include_principal_object_classes) = 0
                OR poc.name IN (SELECT value FROM json_each(:include_principal_object_classes))
            )
            AND (
                :exclude_principal_object_classes IS NULL OR json_array_length(:exclude_principal_object_classes) = 0
                OR poc.name NOT IN (SELECT value FROM json_each(:exclude_principal_object_classes))
            )
        """
        c = self.conn.cursor()
        c.execute(query, filters)
        return c.fetchall()
