ACE_TYPE = {
    "ACCESS_ALLOWED_ACE_TYPE": "Allowed",
    "ACCESS_DENIED_ACE_TYPE": "Denied",
    "ACCESS_ALLOWED_OBJECT_ACE_TYPE": "Allowed Object",
    "ACCESS_DENIED_OBJECT_ACE_TYPE": "Denied Object",
}

MASK = {
    "Create Child": "CREATE_CHILD",  # 0x00000001 - Right to create a child object.
    "Delete Child": "DELETE_CHILD",  # 0x00000002 - Right to delete a child object.
    "List Children": "ACTRL_DS_LIST",  # 0x00000004 - Right to enumerate a DS object.
    "Self": "SELF",  # 0x00000008 - Validated write (e.g., update your own attributes).
    "Read Prop": "READ_PROP",  # 0x00000010 - Right to read properties or property sets.
    "Write Prop": "WRITE_PROP",  # 0x00000020 - Right to write properties or property sets.
    "Delete Tree": "DELETE_TREE",  # 0x00000040 - Right to delete all child objects, regardless of their permissions.
    "List Object": "LIST_OBJECT",  # 0x00000080 - Right to list a specific object (not just children).
    "Extended Right": "CONTROL_ACCESS",  # 0x00000100 - Right to perform extended operations (like password resets).
    "Delete": "DELETE",  # 0x00010000 - Right to delete the object.
    "Read Control": "READ_CONTROL",  # 0x00020000 - Right to read security descriptor (excluding the SACL).
    "Write Dacl": "WRITE_DACL",  # 0x00040000 - Right to modify the DACL.
    "Write Owner": "WRITE_OWNER",  # 0x00080000 - Right to take ownership of the object.
    "Synchronize": "SYNCHRONIZE",  # 0x00100000 - Right to wait on the object (used in threading).
    "Access System Security": "ACCESS_SYSTEM_SECURITY",  # 0x01000000 - Right to view or edit the SACL (audit policy).
    "Maximum Allowed": "MAXIMUM_ALLOWED",  # 0x02000000 - Grants all permissions allowed by the ACL.
    # Composite rights:
    "Generic Execute": "GENERIC_EXECUTE",  # 0x00020004 = READ_CONTROL + ACTRL_DS_LIST
    "Generic Read": "GENERIC_READ",  # 0x00020094 = READ_CONTROL + ACTRL_DS_LIST + LIST_OBJECT + READ_PROP
    "Generic Write": "GENERIC_WRITE",  # 0x00020028 = READ_CONTROL + WRITE_PROP + SELF
    "Generic All": "GENERIC_ALL",  # 0x000F01FF = Full access including: CREATE_CHILD, DELETE_CHILD, DELETE_TREE, LIST_OBJECT, READ_PROP, WRITE_PROP, SELF, CONTROL_ACCESS, DELETE, READ_CONTROL, WRITE_DACL, WRITE_OWNER
}
MASK_INV = {v: k for k, v in MASK.items()}

ACE_FLAG = {
    "Container Inherit": "CONTAINER_INHERIT_ACE",
    "Failed Access": "FAILED_ACCESS_ACE_FLAG",
    "Inherit Only": "INHERIT_ONLY_ACE",
    "Inherited": "INHERITED_ACE",
    "No Propagate Inherit": "NO_PROPAGATE_INHERIT_ACE",
    "Object Inherit": "OBJECT_INHERIT_ACE",
    "Successful Access": "SUCCESSFUL_ACCESS_ACE_FLAG",
}
ACE_FLAG_INV = {v: k for k, v in ACE_FLAG.items()}
