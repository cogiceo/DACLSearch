#! /usr/bin/env python3
import argparse
import logging
import sys
import os
from daclsearch.dump.dump import DACLSearchDump
from daclsearch.cli import DACLSearchCLI


def main():
    parser = argparse.ArgumentParser(description="DACLSearch")

    subparsers = parser.add_subparsers(title="Commands", dest="command", required=True)

    # Dump command
    dump = subparsers.add_parser("dump", help="Dump ACEs into a SQLite database")
    dump.add_argument("--debug", action="store_true", help="Enable debug output")

    connection_parser = dump.add_argument_group(title="Connection")
    connection_parser.add_argument("-d", "--domain", type=str, help="Target domain name")
    connection_parser.add_argument("-l", "--logon-domain", help="Logon domain name")
    connection_parser.add_argument("-u", "--username", type=str, help="Username for authentication")
    connection_parser.add_argument("-p", "--password", type=str, help="Password for authentication")
    connection_parser.add_argument("-H", "--hashes", type=str, help="NTLM hashes (LMHASH:NTHASH)")
    connection_parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    connection_parser.add_argument("--host", type=str, help="Domain Controller hostname")
    connection_parser.add_argument("--dc-ip", type=str, help="Domain Controller IP address")
    connection_parser.add_argument("--aeskey", type=str, help="AES key for Kerberos authentication")
    connection_type = connection_parser.add_mutually_exclusive_group()
    connection_type.add_argument("--ldaps", action="store_true", help="Use LDAPS (port 636)")
    connection_type.add_argument("--gc", action="store_true", help="Use the Global Catalog (port 3268)")

    dump_parser = dump.add_argument_group(title="File options")
    dump_parser.add_argument("-i", "--input", type=str, help="Input LDAP data file (JSON format)", metavar="input_json")
    dump_parser.add_argument(
        "-j", "--json", type=str, help="Output LDAP data to JSON file (optional)", metavar="output_json"
    )
    dump_parser.add_argument("-f", "--full", action="store_true", help="Query all attributes for each object")
    dump_parser.add_argument("output_sqlite", type=str, help="Output SQLite file", metavar="output_sqlite")

    # CLI command
    cli = subparsers.add_parser("cli", help="Run the CLI for DACL search")
    cli.add_argument("input_sqlite", type=str, help="Input SQLite file")
    cli.add_argument("--no-builtin", action="store_true", help="Don't load builtin filters")

    args = parser.parse_args()

    # Logging options
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    if getattr(args, "debug", False):
        logger.setLevel(logging.DEBUG)
    stream = logging.StreamHandler(sys.stderr)

    class CustomFormatter(logging.Formatter):
        def format(self, record):
            if record.levelno == logging.ERROR:
                self._style._fmt = "%(levelname)s: %(message)s [%(filename)s:%(lineno)d]"
            elif record.levelno == logging.DEBUG:
                self._style._fmt = "%(levelname)s: %(message)s"
            else:
                self._style._fmt = "%(message)s"
            return super().format(record)

    formatter = CustomFormatter()
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if args.command == "dump" and not args.input:
        if not args.domain:
            logging.info("The --domain argument is required")
            sys.exit()

        if args.full and not args.json:
            logging.info("Cannot use --full without --json")
            sys.exit()

    if args.command == "dump":
        ldap_args = {
            "dc_ip": args.dc_ip,
            "dc_host": args.host,
            "domain": args.domain,
            "logon_domain": args.logon_domain,
            "username": args.username,
            "password": args.password,
            "hashes": args.hashes,
            "do_kerberos": args.kerberos,
            "aeskey": args.aeskey,
            "use_ldaps": args.ldaps,
            "use_gc": args.gc,
        }
        dumper = DACLSearchDump(ldap_args, db_path=args.output_sqlite, json_path=args.json, input_path=args.input)
        dumper.run(full=args.full)

    elif args.command == "cli":
        if not os.path.exists(args.input_sqlite):
            logging.info(f"File {args.input_sqlite} does not exist")
            sys.exit()

        daclsearch_cli = DACLSearchCLI(args.input_sqlite, args.no_builtin)
        daclsearch_cli.main_menu()


if __name__ == "__main__":
    main()
