import os
import yaml
from importlib import resources

from rich import box
from rich.tree import Tree
from rich.table import Table
from rich.console import Console
from rich.progress import track

from InquirerPy import inquirer
from InquirerPy.utils import get_style
from InquirerPy.base import Choice
from InquirerPy.separator import Separator
from InquirerPy.prompts import FilePathPrompt

from winacl.dtyp.ace import ADS_ACCESS_MASK

from daclsearch.search import DACLSearch
from daclsearch.utils import MASK_INV


class DACLSearchCLI:
    """
    Command-line interface for DACLSearch with interactive filter management and result exploration.
    """

    FILTERS = {
        "principal_names": "Principals Names",
        "principal_object_classes": "Principals Object Classes",
        "target_object_dns": "Targets Object DNs",
        "target_object_classes": "Targets Object Classes",
        "ace_types": "ACE Types",
        "access_masks": "ACE Access Masks",
        "object_types": "ACE Object Types",
        "inherited_object_types": "ACE Inherited Object Types",
        "ace_flags": "ACE Flags",
        "owner_names": "Owners",
    }

    INV_FILTERS = {v: k for k, v in FILTERS.items()}

    def __init__(self, db_path, no_builtin_filters):
        """
        Initialize the CLI with database path and load built-in filters if not disabled.
        """

        self.daclsearch = DACLSearch(db_path)
        self.obj_filters = self.daclsearch.obj_filters

        self.filter_groups = {}
        self.current_group_name = None

        # Default empty filter configuration
        self.default_filters = {f"{ftype}_{key}": [] for ftype in ["include", "exclude"] for key in self.FILTERS.keys()}
        self.default_filters["recursive_search"] = True
        self.default_filters["ownership_search"] = True
        self.default_filters["include_self_rights"] = True
        self.default_filters["merge"] = False

        self.console = Console()

        # Load built-in search and merge filters if not disabled
        if not no_builtin_filters:
            for builtin_name in ["search", "merge"]:
                self.load_builtin_filters(builtin_name)

    def show_filters(self):
        """
        Display current filter configuration in a table.
        """

        current_filters = self.filter_groups[self.current_group_name]
        # Create a table to display filters
        table = Table(box=box.ROUNDED, show_lines=True)
        table.add_column("Type", style="cyan", justify="center")
        table.add_column("Column", style="magenta", justify="center")
        table.add_column("Values", style="green", justify="left")

        # Add rows for each filter type
        for ftype in ["include", "exclude"]:
            for key, value in self.FILTERS.items():
                values = current_filters.get(f"{ftype}_{key}", [])
                if values:
                    table.add_row(ftype.capitalize(), value, ", ".join(values))

        # Add rows for special filters
        special_filters = {
            "recursive_search": "Recursive search",
            "ownership_search": "Ownership search",
            "include_self_rights": "Self rights search",
            "merge": "Merge filter",
        }
        for key, label in special_filters.items():
            if key in current_filters:
                table.add_row("Special", label, "Enabled" if current_filters[key] else "Disabled")
            else:
                default = self.default_filters[key]
                table.add_row("Special", label, "Enabled" if default else "Disabled")

        self.console.print(table)

    def remove_filter(self):
        """
        Interactively remove specific filter of filter group.
        """

        current_filters = self.filter_groups[self.current_group_name]
        self.show_filters()

        # Gather current filters to present as choices
        choices = []
        for ftype in ["include", "exclude"]:
            for key in self.FILTERS.keys():
                values = current_filters.get(f"{ftype}_{key}", [])
                if values:
                    choices.append(f"{ftype}:{key}")
        if not choices:
            self.console.print("[red]No filters to remove.[/red]")
            return

        # Let user select which filters to remove
        result = inquirer.fuzzy(
            message="Select filter(s) to remove:",
            choices=choices,
            multiselect=True,
            keybindings={"toggle-down": {"key": "c-right"}},
            border=True,
            mandatory=False,
            transformer=lambda result: f"Selected {len(result)} filter(s) to remove",
            long_instruction="Type to search | Confirm Enter | Cancel Ctrl+Z | Select: one Ctrl+Right, all Ctrl+A , Invert Ctrl+R",
        ).execute()

        # Remove selected filters
        if result:
            for selected in result:
                ftype, filter_name = selected.split(":")
                key = self.INV_FILTERS[f"{ftype}_{key}"]
                current_filters[f"{ftype}_{key}"] = []
                self.console.print(f"[yellow]Removed filter {ftype.capitalize()} {filter_name}[/yellow]")

    def load_builtin_filters(self, builtin_name, message=None):
        """
        Load built-in filter groups.
        """
        try:
            with resources.path("filters", builtin_name) as folder:
                self.load_filters(str(folder), message=message)
        except Exception as e:
            self.console.print(f"[red]Could not load default filter groups from {builtin_name}: {e}[/red]")

    def load_filters(self, path, message=None):
        """
        Load multiple filter groups from YAML files in a specified folder or a single file.
        """

        # Determine if path is a directory or file
        if os.path.isdir(path):
            filter_files = [fname for fname in os.listdir(path) if fname.endswith(".yaml") or fname.endswith(".yml")]
            if not filter_files:
                self.console.print(f"[yellow]No filter YAML files found in {path}[/yellow]")
                return
        elif os.path.isfile(path) and (path.endswith(".yaml") or path.endswith(".yml")):
            filter_files = [os.path.basename(path)]
            path = os.path.dirname(path)
        else:
            self.console.print(f"[red]Invalid path: {path}[/red]")
            return

        # Load and parse each YAML filter file
        previews = []
        file_map = {}
        title_choices = []

        for fname in filter_files:
            fpath = os.path.join(path, fname)
            try:
                with open(fpath, "r") as f:
                    data = yaml.safe_load(f)

                title = data.get("title", fname)
                desc = data.get("description", "")
                preview = f"{title} - {desc} ({fname})"
                previews.append(preview)
                file_map[title] = (title, data)
                title_choices.append(title)
            except Exception as e:
                self.console.print(f"[yellow]Could not load filter {fname}: {e}[/yellow]")

        # Let user select which filter groups to load if message is provided
        if message:
            selected = inquirer.fuzzy(
                message=message,
                choices=sorted(title_choices),
                multiselect=True,
                keybindings={"toggle-down": {"key": "c-right"}},
                border=True,
                mandatory=False,
                transformer=lambda result: f"Loaded {len(result)} filter group(s)",
                long_instruction="Type to search | Confirm Enter | Cancel Ctrl+Z | Select: one Ctrl+Right, all Ctrl+A , Invert Ctrl+R",
            ).execute()
            if not selected:
                return
        else:
            selected = title_choices

        # Add selected filter groups to self.filter_groups
        for title in selected if isinstance(selected, list) else [selected]:
            _, data = file_map[title]
            filter_data = {k: v for k, v in data.items() if k not in ("title", "description")}
            merge_flag = filter_data.get("merge", False)

            group = self.default_filters.copy()
            group["recursive_search"] = filter_data.get("recursive_search", True)
            group["ownership_search"] = filter_data.get("ownership_search", True)
            group["include_self_rights"] = filter_data.get("include_self_rights", True)
            group["merge"] = merge_flag
            for filter, value in filter_data.items():
                group[filter] = value

            self.filter_groups[title] = group

    def load_filter_groups_menu(self):
        """
        Select a custom filter groups from a file or folder.
        """
        with resources.path("filters", "custom") as path:
            default_path = str(path)

        path = FilePathPrompt(
            message="Select file or folder to load (empty to load default custom filters):",
            only_directories=False,
            mandatory=False,
        ).execute()

        if path == "":
            path = default_path

        if path is not None:
            if os.path.isdir(path):
                self.load_filters(path, "Select filter group(s) to load:")
                return
            elif os.path.isfile(path):
                self.load_filters(path)

    def print_ownership_tree(self, owned_objs, ownership_enabled, title):
        """
        Print ownership information in a hierarchical tree structure.
        """
        tree = Tree(f"[bold]{title}[/bold]")
        if ownership_enabled and owned_objs:
            for obj_dn in owned_objs:
                tree.add(f"[bold blue]{obj_dn}[/bold blue]")
        self.console.print(tree)

    def filter_search_output(self, aces, title, detailed=True):
        """
        Output for filter search queries.
        """

        dn_map = {}
        for ace in aces:
            dn = ace.get("Object DN", "")
            if dn not in dn_map:
                dn_map[dn] = []
            dn_map[dn].append(ace)

        # If too many ACEs, let user select which Object DN(s) to display
        if detailed and len(dn_map) > 20 and dn_map:
            dn_choices = sorted(list(dn_map.keys()))
            selected_dns = inquirer.fuzzy(
                message="Too many ACEs. Select Object DN(s) to display:",
                choices=dn_choices,
                multiselect=True,
                keybindings={"toggle-down": {"key": "c-right"}},
                match_exact=True,
                border=True,
                mandatory=False,
                transformer=lambda result: f"Selected {len(result)} DN to display",
                long_instruction="Type to search | Confirm Enter | Cancel Ctrl+Z | Select: one Ctrl+Right, all Ctrl+A , Invert Ctrl+R",
            ).execute()
            if not selected_dns:
                return
            if isinstance(selected_dns, str):
                selected_dns = [selected_dns]
            dn_items = [(dn, dn_map[dn]) for dn in selected_dns]
        else:
            dn_items = dn_map.items()

        self.print_aces(f"[bold]{title}[/bold]", dn_items)

    def print_aces(self, title, items):
        """
        Print ACEs in a tree structure.
        """

        tree = Tree(title)
        for name, ace_list in sorted(items):

            obj_subnode = tree.add(f"[bold blue]{name}[/bold blue]")

            # Create a table for ACEs

            table = Table(title=None, box=box.ROUNDED, show_lines=True, min_width=42)
            table.add_column("Access Type", min_width=7, width=18, vertical="middle")
            table.add_column("Access Rights", style="bold", overflow="fold", min_width=8, width=20, vertical="middle")
            table.add_column("Flags", style="yellow", min_width=12, width=24, vertical="middle")

            # Adjust column widths based on console width
            if self.console.size.width < 178:
                table.add_column("Object Type", overflow="fold", ratio=1, vertical="middle")
                table.add_column("Inherited Object Type", ratio=1, vertical="middle")
            else:
                table.add_column("Object Type", overflow="fold", width=50, vertical="middle")
                table.add_column("Inherited Object Type", width=50, vertical="middle")

            # Add ACEs to the tree
            if ace_list:
                for ace in ace_list:
                    rights = []
                    mask_value = ace.get("Access Mask", 0)
                    mask_names = [name for name in ADS_ACCESS_MASK.__members__]

                    # Sort mask names by number of bits set (descending)
                    mask_names_sorted = sorted(
                        mask_names,
                        key=lambda n: bin(getattr(ADS_ACCESS_MASK, n).value).count("1"),
                        reverse=True,
                    )

                    # Return only the highest matching rights
                    for name in mask_names_sorted:
                        mask_enum = getattr(ADS_ACCESS_MASK, name)
                        if mask_enum.value != 0 and (mask_value & mask_enum.value) == mask_enum.value:
                            rights.append(name)
                            mask_value &= ~mask_enum.value

                    # Rights to display format
                    display_rights = []
                    for r in rights:
                        if r in MASK_INV:
                            display_rights.append(MASK_INV[r])
                        else:
                            display_rights.append(r)
                    display_rights = sorted([d for d in display_rights if d is not None])

                    access_rights = "\n".join(display_rights) if display_rights else ""
                    ace_flags = "\n".join(ace.get("Flags", [])) if ace.get("Flags") else ""
                    access_type = ace.get("Access Type", "")
                    access_type = (
                        f"[green]{access_type}[/green]" if "Allowed" in access_type else f"[red]{access_type}[/red]"
                    )

                    table.add_row(
                        access_type,
                        access_rights,
                        ace_flags,
                        ace.get("Object Type", ""),
                        ace.get("Inherited Object Type", ""),
                    )
            obj_subnode.add(table)
        self.console.print(tree)

    def object_search(self):
        """
        Find ACEs applied on an object
        """
        while True:
            menu_choices = {"SID": "sid", "SAM Account Name": "name", "Distinguished Name": "dn"}
            choice = inquirer.select(
                message="Search based on:",
                choices=menu_choices.keys(),
                mandatory=False,
                border=True,
            ).execute()
            if choice is None:
                return

            col = menu_choices[choice]

            object_val = inquirer.fuzzy(
                message="Select an object:",
                choices=self.daclsearch.all_objects.get(col),
                multiselect=False,
                border=True,
                mandatory=False,
            ).execute()
            if object_val is None:
                continue

            object_dn, aces = self.daclsearch.get_object_ace(col, object_val)
            if object_dn and aces:
                self.print_aces(f"All ACEs on {object_dn}", aces.items())

    def explore_results(self, results):
        """
        Interactively explore search results.
        """

        result_principals = results.get("result_principals", {})
        obj_rights = results.get("obj_rights", {})
        memberships = results.get("memberships", {})
        ownerships = results.get("ownerships", {})
        ownership_enabled = results.get("ownership_search", True)

        if not isinstance(result_principals, dict) or not result_principals or not any(result_principals.values()):
            self.console.print("[yellow]No principals found in results.[/yellow]")
            return

        # Sort classes by number of principals (desc), then by class name asc
        sorted_classes = sorted(result_principals.items(), key=lambda item: (-len(item[1]), item[0].lower()))

        class_choices = []
        for class_name, principals in sorted_classes:
            class_choices.append(f"{class_name} ({len(principals)})")

        class_to_principals = {}
        for class_name, principals in sorted_classes:
            class_to_principals[class_name] = principals

        # Select principal class
        while True:
            selected_class = inquirer.select(
                message="Select principal class:",
                choices=class_choices,
                border=True,
                mandatory=False,
            ).execute()
            if selected_class is None:
                return

            # Select principals within the class
            while True:
                class_name = selected_class.rsplit(" ", 1)[0]
                principals = class_to_principals.get(class_name, [])

                # Get the number of objects a principal as rights on
                principals_obj_sum = {}
                for principal in principals:
                    sum = 0
                    for group in memberships.get(principal, []):
                        sum += len(obj_rights.get(group, []))
                    sum += len(obj_rights.get(principal, []))
                    principals_obj_sum[principal] = sum

                sorted_principals_obj = sorted(principals_obj_sum.items(), key=lambda item: (-item[1], item[0].lower()))
                principals_obj = []
                for principal, number in sorted_principals_obj:
                    principals_obj.append(f"{principal} ({number})")

                selected_principals = inquirer.fuzzy(
                    message=f"Select principals or one principal for details:",
                    choices=principals_obj,
                    multiselect=True,
                    keybindings={"toggle-down": {"key": "c-right"}},
                    border=True,
                    mandatory=False,
                    transformer=lambda result: f"Selected {len(result)} principal(s)",
                    long_instruction="Type to search | Confirm Enter | Cancel Ctrl+Z | Select: one Ctrl+Right, all Ctrl+A , Invert Ctrl+R",
                ).execute()
                if not selected_principals:
                    break

                detailed = len(selected_principals) == 1
                for principal in selected_principals:
                    principal = principal.rsplit(" ", 1)[0]

                    # Determine choices based on available data
                    all_groups = memberships.get(principal, [])
                    groups_with_data = []
                    for group in all_groups:
                        has_rights = group in obj_rights and obj_rights[group]
                        has_ownerships = group in ownerships and ownerships[group]
                        if has_rights or has_ownerships:
                            groups_with_data.append(group)

                    direct_aces_exist = bool(obj_rights.get(principal, []))
                    direct_ownerships_exist = ownership_enabled and bool(ownerships.get(principal, []))
                    group_aces_exist = any(obj_rights.get(g, []) for g in groups_with_data)
                    group_ownerships_exist = ownership_enabled and any(ownerships.get(g, []) for g in groups_with_data)

                    while True:
                        if detailed:
                            menu_choices = []
                            if direct_aces_exist and group_aces_exist:
                                menu_choices.append("All ACEs")
                            if direct_aces_exist:
                                menu_choices.append("Direct ACEs")
                            if group_aces_exist:
                                menu_choices.append("Group(s) ACEs")
                            if direct_ownerships_exist and group_ownerships_exist:
                                menu_choices.append("All Ownerships")
                            if direct_ownerships_exist:
                                menu_choices.append("Direct Ownerships")
                            if group_ownerships_exist:
                                menu_choices.append("Group(s) Ownerships")

                            action = inquirer.select(
                                message=f"Explore for principal {principal}:",
                                choices=menu_choices,
                                border=True,
                                mandatory=False,
                            ).execute()
                            if action is None:
                                break
                        else:
                            action = "All ACEs"

                        # Print ACEs or ownerships based on user selection
                        if action == "All ACEs":
                            all_aces = []
                            if principal in obj_rights:
                                for obj_dn, aces in obj_rights[principal].items():
                                    for ace in aces:
                                        ace = dict(ace)
                                        ace["Object DN"] = obj_dn
                                        all_aces.append(ace)
                            for group in groups_with_data:
                                if group in obj_rights:
                                    for obj_dn, aces in obj_rights[group].items():
                                        for ace in aces:
                                            ace = dict(ace)
                                            ace["Trustee"] = group
                                            ace["Object DN"] = obj_dn
                                            all_aces.append(ace)
                            owned_objs = []
                            self.filter_search_output(all_aces, title=f"All ACEs of {principal}", detailed=detailed)

                        elif action == "Direct ACEs":
                            direct_aces = []
                            if principal in obj_rights:
                                for obj_dn, aces in obj_rights[principal].items():
                                    for ace in aces:
                                        ace = dict(ace)
                                        ace["Object DN"] = obj_dn
                                        direct_aces.append(ace)
                            owned_objs = []
                            self.filter_search_output(direct_aces, title=f"Direct ACEs of {principal}")

                        elif action == "Group(s) ACEs":
                            group = inquirer.fuzzy(
                                message="Select group:",
                                choices=groups_with_data,
                                multiselect=False,
                                border=True,
                                mandatory=False,
                            ).execute()
                            if group is None:
                                continue
                            group_aces = []
                            if group in obj_rights:
                                for obj_dn, aces in obj_rights[group].items():
                                    for ace in aces:
                                        ace = dict(ace)
                                        group_aces.append(ace)
                            self.filter_search_output(group_aces, title=f"Group {group} ACEs")

                        elif action == "All Ownerships":
                            owned_objs = ownerships.get(principal, [])
                            for group in groups_with_data:
                                owned_objs += ownerships.get(group, [])
                            self.print_ownership_tree(
                                owned_objs, ownership_enabled, title=f"All Ownerships of {principal}"
                            )

                        elif action == "Direct Ownerships":
                            owned_objs = ownerships.get(principal, [])
                            self.print_ownership_tree(
                                owned_objs, ownership_enabled, title=f"Direct Ownerships of {principal}"
                            )

                        elif action == "Group(s) Ownerships":
                            groups_with_ownerships = [g for g in groups_with_data if ownerships.get(g, [])]
                            group = inquirer.fuzzy(
                                message="Select group:",
                                choices=groups_with_ownerships,
                                multiselect=False,
                                border=True,
                                mandatory=False,
                            ).execute()
                            if group is None:
                                continue

                            owned_objs = ownerships.get(group, [])
                            self.print_ownership_tree(owned_objs, ownership_enabled, title=f"Group {group} Ownerships")

                        # Exit if multiple principals were selected
                        if not detailed:
                            break

    def save_filter_groups_menu(self):
        """
        Save selected filter groups to YAML files in a specified folder.
        """

        # Select filter groups to save
        choices = [f"{name}" for name in self.filter_groups.keys()]
        selected = inquirer.fuzzy(
            message="Select filter group(s) to save:",
            choices=choices,
            multiselect=True,
            keybindings={"toggle-down": {"key": "c-right"}},
            border=True,
            mandatory=False,
            transformer=lambda result: f"Selected {len(result)} filter group(s) to save",
            long_instruction="Type to search | Confirm Enter | Cancel Ctrl+Z | Select: One Ctrl+Right, All Ctrl+A , Invert Ctrl+R",
        ).execute()
        if not selected:
            return

        # Select folder to save filter groups
        folder = FilePathPrompt(
            message="Enter folder path to save filter groups:",
            only_directories=True,
            mandatory=False,
        ).execute()
        if not folder or not os.path.isdir(folder):
            self.console.print(f"[red]Invalid folder: {folder}[/red]")
            return

        # Save each selected filter group to a YAML file
        for group_name in selected if isinstance(selected, list) else [selected]:
            group = self.filter_groups[group_name]
            desc = inquirer.text(
                message=f"Enter description for '{group_name}' (leave blank to skip):",
                mandatory=False,
            ).execute()

            data = dict(group)
            data["title"] = group_name
            data = {k: v for k, v in data.items() if v not in ([], None)}
            if desc:
                data["description"] = desc

            filename = os.path.join(folder, f"{group_name.replace(' ','_').lower()}.yaml")
            with open(filename, "w") as f:
                yaml.dump(data, f)
            self.console.print(f"[green]Saved filter group '{group_name}' to '{filename}'[/green]")

    def filter_config(self):
        """
        Configure filters for a specific group.
        """
        filters = self.filter_groups[self.current_group_name]

        while True:
            menu_choices = [
                "Show configuration",
                "Add inclusion filter",
                "Add exclusion filter",
                "Special filters",
                "Remove filter",
            ]
            action = inquirer.select(
                message=f"Configure '{self.current_group_name}' filter group:",
                choices=menu_choices,
                mandatory=False,
                border=True,
                long_instruction="Select Enter | Cancel Ctrl+Z",
            ).execute()
            if action is None:
                return

            if action == "Show configuration":
                self.show_filters()

            elif action in ["Add inclusion filter", "Add exclusion filter"]:
                ftype = "include" if action == "Add inclusion filter" else "exclude"
                filter_name = inquirer.select(
                    message="Select column to filter:",
                    choices=self.FILTERS.values(),
                    mandatory=False,
                    border=True,
                    long_instruction="Select Enter | Cancel Ctrl+Z",
                ).execute()
                if filter_name is None:
                    continue

                key = self.INV_FILTERS[filter_name]
                options = self.obj_filters.get(key, [])
                match_exact = key == "target_object_dns"

                preselected = filters.get(f"{ftype}_{key}", [])
                if preselected is None:
                    preselected = []
                choices = [Choice(opt, enabled=(opt in preselected)) for opt in options]

                selected = inquirer.fuzzy(
                    message="Search and select values:",
                    choices=choices,
                    multiselect=True,
                    keybindings={"toggle-down": {"key": "c-right"}},
                    mandatory=False,
                    max_height=10,
                    border=True,
                    transformer=lambda result: f"Selected {len(result)} value(s)",
                    long_instruction="Type to search | Confirm Enter | Cancel Ctrl+Z | Select: one Ctrl+Right, all Ctrl+A , Invert Ctrl+R",
                    match_exact=match_exact,
                ).execute()

                if selected is None:
                    continue

                filters[f"{ftype}_{key}"] = selected if isinstance(selected, list) else [selected]

            elif action == "Special filters":
                config_choices = [
                    f"{'Enable' if not filters.get('recursive_search', True) else 'Disable'} recursive search",
                    f"{'Enable' if not filters.get('ownership_search', True) else 'Disable'} ownership search",
                    f"{'Enable' if not filters.get('include_self_rights', True) else 'Disable'} self rights search",
                    f"{'Enable' if not filters.get('merge', False) else 'Disable'} merge",
                ]
                config_action = inquirer.select(
                    message="Filter configuration:",
                    choices=config_choices,
                    border=True,
                    mandatory=False,
                ).execute()
                if config_action is None:
                    continue
                if "recursive search" in config_action:
                    filters["recursive_search"] = not filters.get("recursive_search", True)
                    self.console.print(
                        f"[cyan]Recursive search is now {'enabled' if filters['recursive_search'] else 'disabled'}[/cyan]"
                    )
                elif "ownership search" in config_action:
                    filters["ownership_search"] = not filters.get("ownership_search", True)
                    self.console.print(
                        f"[cyan]Ownership search is now {'enabled' if filters['ownership_search'] else 'disabled'}[/cyan]"
                    )
                elif "self rights search" in config_action:
                    filters["include_self_rights"] = not filters.get("include_self_rights", True)
                    self.console.print(
                        f"[cyan]Self rights search is now {'enabled' if filters['include_self_rights'] else 'disabled'}[/cyan]"
                    )
                elif "merge" in config_action:
                    filters["merge"] = not filters.get("merge", False)
                    self.console.print(f"[cyan]Merge is now {'enabled' if filters['merge'] else 'disabled'}[/cyan]")

            elif action == "Remove filter":
                self.remove_filter()

    def manage_filters(self):
        """
        Menu to manage filter groups interactively.
        """

        while True:
            menu_choices = [
                Separator("Filter Groups"),
                "Configure group",
                "Select group",
                "Create group",
                "Rename group",
                "Delete group",
                "Save filter groups",
                Separator("Load"),
                "Load search filter(s)",
                "Load merge filter(s)",
                "Load custom filter(s)",
            ]
            action = inquirer.select(
                message=f"Filter group menu (currently selected: {self.current_group_name if self.current_group_name else 'None'}):",
                choices=menu_choices,
                mandatory=False,
                border=True,
                style=get_style({"separator": "underline bold"}, style_override=False),
                long_instruction="Select Enter | Cancel Ctrl+Z",
            ).execute()

            if action is None:
                return
            elif action == "Select group":
                if not self.filter_groups:
                    self.console.print("[red]No filter groups available to select.[/red]")
                    continue

                # Select from existing filter groups
                group_names = sorted(list(self.filter_groups.keys()))
                selected = inquirer.fuzzy(
                    message="Select filter group:",
                    choices=group_names,
                    border=True,
                    mandatory=False,
                ).execute()
                if selected is not None:
                    self.current_group_name = selected
            elif action == "Create group":
                new_name = inquirer.text(
                    message="Enter new filter group name:",
                    mandatory=False,
                ).execute()

                # Check if name is valid and does not already exist
                if new_name and new_name not in self.filter_groups:
                    self.filter_groups[new_name] = self.default_filters.copy()
                    self.current_group_name = new_name
                else:
                    self.console.print(f"[red]Filter group '{new_name}' already exists or invalid name.[/red]")

            elif action == "Rename group":
                if not self.filter_groups:
                    self.console.print("[red]No filter groups available to rename.[/red]")
                    continue
                group_names = list(self.filter_groups.keys())
                rename_choices = [name for name in group_names if name != self.current_group_name]
                if not rename_choices:
                    self.console.print("[red]No other filter groups to rename.[/red]")
                    continue

                # Select from existing filter groups to rename
                old_name = inquirer.fuzzy(
                    message="Select filter group to rename:",
                    choices=rename_choices,
                    border=True,
                    mandatory=False,
                ).execute()

                if old_name:
                    new_name = inquirer.text(
                        message=f"Enter new name for '{old_name}':",
                        mandatory=False,
                    ).execute()
                    if new_name and new_name not in self.filter_groups:
                        self.filter_groups[new_name] = self.filter_groups.pop(old_name)
                        if self.current_group_name == old_name:
                            self.current_group_name = new_name
                        self.console.print(f"[green]Renamed filter group '{old_name}' to '{new_name}'[/green]")
                    else:
                        self.console.print(f"[red]Filter group '{new_name}' already exists or invalid name.[/red]")

            elif action == "Delete group":
                if not self.filter_groups:
                    self.console.print("[red]No filter groups available to delete.[/red]")
                    continue

                # Select from existing filter groups to delete
                group_names = list(self.filter_groups.keys())
                delete_choices = [name for name in group_names]
                to_delete = inquirer.fuzzy(
                    message="Select filter group(s) to delete:",
                    choices=delete_choices,
                    multiselect=True,
                    keybindings={"toggle-down": {"key": "c-right"}},
                    border=True,
                    transformer=lambda result: f"Removed {len(result)} filter group(s)",
                    mandatory=False,
                ).execute()

                if to_delete:
                    for name in to_delete if isinstance(to_delete, list) else [to_delete]:
                        self.filter_groups.pop(name, None)
                    if self.current_group_name not in self.filter_groups:
                        self.current_group_name = None

            elif action == "Load search filter(s)":
                self.load_builtin_filters("search", message="Select default search filter group(s) to load:")
            elif action == "Load merge filter(s)":
                self.load_builtin_filters("merge", message="Select default merge filter group(s) to load:")
            elif action == "Load custom filter(s)":
                self.load_filter_groups_menu()
            elif action == "Save filter groups":
                if not self.filter_groups:
                    self.console.print("[red]No filter groups to save.[/red]")
                    continue
                self.save_filter_groups_menu()
            elif action == "Configure group":
                if self.current_group_name is None or self.current_group_name not in self.filter_groups:
                    self.console.print(
                        "[red]No filter group selected. Please create or select a filter group first.[/red]"
                    )
                    continue
                self.filter_config()

    def merge_filters(self, selected_group_names):
        """
        Merge selected filter groups into a single filter.
        """

        # Process selected groups
        merged = {}
        for group_name in selected_group_names:
            group = self.filter_groups[group_name]
            for k, v in group.items():
                if k == "merge":
                    continue
                if isinstance(v, list):
                    merged.setdefault(k, set()).update(v)
                elif isinstance(v, bool):
                    if not v:
                        merged[k] = v

        # Convert sets back to lists
        for k in merged:
            if isinstance(merged[k], set):
                merged[k] = list(merged[k])
        for ftype in ["include", "exclude"]:
            for key in self.FILTERS.keys():
                merged.setdefault(f"{ftype}_{key}", [])
        merged.setdefault("recursive_search", True)
        merged.setdefault("ownership_search", True)
        merged.setdefault("include_self_rights", True)
        return merged

    def merge_results(self, search_results):
        """
        Merge multiple search results into a single result.
        """

        def ace_to_tuple(ace):
            items = []
            for k, v in sorted(ace.items()):
                if isinstance(v, list):
                    items.append((k, tuple(v)))
                else:
                    items.append((k, v))
            return tuple(items)

        merged = {
            "result_principals": {},
            "obj_rights": {},
            "memberships": {},
            "ownerships": {},
            "ownership_search": False,
        }

        for result in search_results:
            # Merge principals
            for class_name, principals in result.get("result_principals", {}).items():
                if class_name not in merged["result_principals"]:
                    merged["result_principals"][class_name] = []
                merged["result_principals"][class_name].extend(principals)

            # Remove duplicates in principals
            for class_name in merged["result_principals"]:
                merged["result_principals"][class_name] = list(set(merged["result_principals"][class_name]))

            # Merge ownership search flag
            merged["ownership_search"] = merged["ownership_search"] or result.get("ownership_search", False)

            # Merge object rights
            for principal, obj_map in result.get("obj_rights", {}).items():
                if principal not in merged["obj_rights"]:
                    merged["obj_rights"][principal] = {}

                for obj_dn, aces in obj_map.items():
                    existing_aces = merged["obj_rights"][principal].setdefault(obj_dn, [])
                    ace_tuples = {ace_to_tuple(a) for a in existing_aces}
                    for ace in aces:
                        ace_tuple = ace_to_tuple(ace)
                        if ace_tuple not in ace_tuples:
                            existing_aces.append(ace)
                            ace_tuples.add(ace_tuple)

            # Merge memberships
            for principal, groups in result.get("memberships", {}).items():
                merged["memberships"].setdefault(principal, set()).update(groups)

            # Merge ownerships
            for principal, owned_objs in result.get("ownerships", {}).items():
                merged["ownerships"].setdefault(principal, set()).update(owned_objs)

        merged["memberships"] = {k: list(set(v)) for k, v in merged["memberships"].items()}
        merged["ownerships"] = {k: list(set(v)) for k, v in merged["ownerships"].items()}
        return merged

    def fitler_search(self):
        """
        Run a search with the given filters and explore the results.
        """

        search_group_names = [name for name, group in self.filter_groups.items() if not group.get("merge", False)]
        merge_group_names = [name for name, group in self.filter_groups.items() if group.get("merge", False)]

        # If no filter groups defined, run default search
        if not search_group_names and not merge_group_names:
            self.console.print("[yellow]No filter groups defined. Running default search.[/yellow]")
            results = self.daclsearch.search(self.default_filters)
            self.explore_results(results)
            return

        # Prompt for search groups if any exist
        if search_group_names:
            search_choices = [
                Choice(name, enabled=(name == self.current_group_name)) for name in sorted(search_group_names)
            ]

            selected_search_groups = inquirer.fuzzy(
                message="Select search filter group(s):",
                choices=search_choices,
                multiselect=True,
                keybindings={"toggle-down": {"key": "c-right"}},
                border=True,
                mandatory=False,
                transformer=lambda result: f"Loaded {len(result)} search filter group(s)",
                long_instruction="Type to search | Confirm Enter | Ctrl+Z Cancel/Skip | Select: One Ctrl+Right, All Ctrl+A , Invert Ctrl+R",
            ).execute()

            # If no search groups selected, confirm to continue with no search filter
            if not selected_search_groups:
                continue_without_search = inquirer.confirm(
                    message="Continue with no search filter ?",
                    mandatory=False,
                    default=True,
                    long_instruction="Continue Enter | Go back Crtl+Z",
                ).execute()

                if continue_without_search:
                    selected_search_groups = []
                else:
                    return

        # Prompt for merge groups if any exist
        selected_merge_groups = []
        if merge_group_names:
            merge_choices = sorted(merge_group_names)
            selected_merge_groups = inquirer.fuzzy(
                message="Select merge filter group(s) :",
                choices=merge_choices,
                multiselect=True,
                keybindings={"toggle-down": {"key": "c-right"}},
                border=True,
                mandatory=False,
                transformer=lambda result: f"Selected {len(result)} merge filter group(s)",
                long_instruction="Type to search | Confirm Enter | Ctrl+Z Cancel/Skip | Select: One Ctrl+Right, All Ctrl+A , Invert Ctrl+R",
            ).execute()

            # If no merge groups selected, confirm to continue with no merge filter
            if not selected_merge_groups:
                continue_without_merge = inquirer.confirm(
                    message="Continue with no merge filter ?",
                    mandatory=False,
                    default=True,
                    long_instruction="Continue Enter | Go back Crtl+Z",
                ).execute()

                if continue_without_merge:
                    selected_merge_groups = []
                else:
                    return

        search_results = {}

        # Run search for each selected search group with optional merge groups
        if selected_search_groups:
            for search_group in track(selected_search_groups, description="> Processing :"):
                if selected_merge_groups:
                    search_filters = self.merge_filters([search_group] + selected_merge_groups)
                else:
                    search_filters = self.filter_groups[search_group]

                search_result = self.daclsearch.search(search_filters)

                if search_result:
                    search_results[search_group] = search_result

            if search_results:
                while True:
                    # Select which search results to display
                    display_results = inquirer.fuzzy(
                        message="Select results to display (merged if multiple):",
                        choices=search_results.keys(),
                        multiselect=True,
                        keybindings={"toggle-down": {"key": "c-right"}},
                        border=True,
                        mandatory=False,
                        transformer=lambda result: f"Selected {len(result)} result(s) to display",
                        long_instruction="Type to search | Confirm Enter | Cancel Ctrl+Z | Select: One Ctrl+Right, All Ctrl+A , Invert Ctrl+R",
                    ).execute()
                    if not display_results:
                        break

                    selected_results = [search_results[result] for result in display_results]
                    merged_results = self.merge_results(selected_results)

                    self.explore_results(merged_results)
            else:
                self.console.print("[yellow]No principals found in results.[/yellow]")

        # Run single search with merged merge groups if no search groups selected
        else:
            if selected_merge_groups:
                merged_filters = self.merge_filters(selected_merge_groups)
                search_results = self.daclsearch.search(merged_filters)
            else:
                self.console.print("[yellow]No search filter group selected. Running default search.[/yellow]")
                search_results = self.daclsearch.search(self.default_filters)

            if search_results:
                self.explore_results(search_results)
            else:
                self.console.print("[yellow]No principals found in results.[/yellow]")

    def main_menu(self):
        """
        Main interactive menu loop.
        """

        exit_confirmed = False
        while True:
            try:
                menu_choices = ["Search ACEs of principals", "Manage filters", "Search ACEs on object", "Exit"]
                action = inquirer.select(
                    message="Choose an action:",
                    choices=menu_choices,
                    mandatory=False,
                    border=True,
                ).execute()
                if action is None:
                    continue
                exit_confirmed = False

                if action == "Search ACEs of principals":
                    self.fitler_search()
                elif action == "Manage filters":
                    self.manage_filters()
                elif action == "Search ACEs on object":
                    self.object_search()

                elif action == "Exit":
                    break

            except KeyboardInterrupt:
                if exit_confirmed:
                    break
                else:
                    exit_confirmed = True
                    self.console.print("[yellow]Press Ctrl+C to exit, or any key to continue.[/yellow]")
                    try:
                        input()
                    except KeyboardInterrupt:
                        break
                    exit_confirmed = False
