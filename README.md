# DACLSearch

**DACLSearch** is a tool designed to exhaustively retrieve the **Access Control Entries (ACEs)** that principals have on any Active Directory objects.

https://github.com/user-attachments/assets/3cae0680-02c9-46fa-8eee-7e35bbe1d382

---

## Installation

### Install with pip

```bash
git clone "https://github.com/cogiceo/daclsearch"
cd daclsearch
pip install .
```

### Install with pipx

```bash
pipx install "git+https://github.com/cogiceo/daclsearch"
```

---

## Dump

Since the tool is exhaustive, the database size will increase, and query performance will decrease proportionally to the size of the Active Directory.

### Quick dump

```bash
daclsearch dump "${DOMAIN}_aces.db" -d $DOMAIN --dc-ip $DC_IP -u $USER -p $PASS
```

> [!NOTE]
> The LDAP query leverages the [Phantom Root](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/782fa852-2aef-42cd-b3d7-3f7a85861289) search flag, which instructs the server to enumerate all naming context (NC) replicas (except for application NCs) subordinate to the search base, even when the search base is not instantiated on the server. As a result, the query retrieves domain objects from all domains within the same forest.

### Dumping with LDAP data to JSON

```bash
daclsearch dump -d $DOMAIN --dc-ip $DC_IP -u $USER -p $PASS --json "${DOMAIN}_ldap.json" "${DOMAIN}_aces.db" 
```

### Building the database from JSON

```bash
daclsearch dump -i "${DOMAIN}_ldap.json" "${DOMAIN}_aces.db" 
```

---

## CLI

### Starting the CLI

```bash
daclsearch cli "${DOMAIN}_aces.db"

? Choose an action: 
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│❯ Search ACEs of principals                                                              │
│  Manage filters                                                                         │ 
│  Search ACEs on object                                                                  │
│  Exit                                                                                   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Search ACEs of principals

This search type retrieves all ACEs that principals have on Active Directory objects.
To narrow results, you can apply filters. Two types of filters are supported:

- **Search filters**: Run independently and return separate result sets. If you select multiple search filters, results from each are returned separately and are merged if you choose multiple results.
- **Merge filters**: Combined with each search filter before querying. If you select multiple merge filters, each one is applied to every search filter.

#### Manage Filters

This menu allows you to:

- Build your own filters based on inclusion or exclusion of:
  - Principal names
  - Principal object classes
  - Target object DNs
  - Target object classes
  - ACE types 
  - ACE access masks
  - ACE object types
  - ACE inherited object types
  - ACE flags
  - Owners
  - Special filters
- Save custom filters in **YAML** format for reuse.
- Load groups of filters from folder or file.
- Use built-in filters based common ACEs abuse, which are loaded automatically when the CLI starts.

#### Search ACEs on object

This search type directly returns the ACEs that principals have on a specific Active Directory object. You can target the object using the following identifiers:

- SID
- SAM Account Name
- Distinguished Name

## Improvements

- [ ] Filtering out default ACEs based on the `defaultSecurityDescriptor` attribut
- [ ] LDAP dump using ADWS
