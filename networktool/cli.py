#!/usr/bin/env python

import sys

from riposte import Riposte
from riposte.printer import Palette

import scans, sourcenetworks, targets, rules

COMMANDS = ["scans", "rules", "sourcenetworks", "targets"]

SCANS_SUBCOMMANDS = ["new", "list", "show", "export", "kill", "rm", "clean"]
SCANS_NEW_SUBCOMMANDS = ["recon", "serviceid", "segmentation-check", "generic", "custom-nmap"]
SCANS_HELP_NEW = f"""
  - \033[1mscans new ({" | ".join(SCANS_NEW_SUBCOMMANDS)})\033[0m
      Starts a new scan (nmap run) based on several pre-defined templates per scan type.
      
      A typical workflow will consist of an initial 'recon' scan to identify services in the local 
      network. Then other types of scans can be run, either from the results of the previous recon 
      scan, or by indicating targets and ports manually.

      Each running Scan is associated with a background nmap process (ran via subprocess.Popen)
      that will trigger a callback every two seconds. This callback will provide its current status
      and completion percentage. This is leveraged by the tool to update the database, so that every
      time 'scans list' is ran (refer to the next subcommand) the displayed status is up to date.

      When creating a new Scan, it will be associated to any existing Rule, SourceNetwork or Target
      that matches the source or destination IPs (depending on the case).
      
      The nmap process handling is managed via the libnmap library.
      
      Usage of the subcommands:

      - recon - Scans aimed at identifying live targets in the current network segment (obtained
                via the local interface's IP and netmask).
                Usage: scans new recon
        
      - serviceid - Scans aimed at fingerprinting services. Need to be provided either target
                    IP range and ports, or a Scan ID. If the latter is specified, the user will be
                    prompted to select between the previously identified live hosts and services.
                    Example 1: scans new serviceid 192.168.1.4 80-tcp,8080-8090-tcp
                    Example 2: scans new serviceid fromscanid 4
      
      - segmentation-check - Scans aimed at bypassing firewall protection mechanisms, signaling
                             potential information exfiltration capabilities.
                             Example 1: scans new segmentation-check
                             Example 2: scans new segmentation-check 192.168.2.0/24
       
      - generic - Several generic nmap scans. Need to be provided either target IP range and ports,
                  or a Scan ID ("fromscanid" subcommand). If the latter is specified, the user will be
                  prompted to select between the previously identified live hosts and services.
                  Example 1: scans new generic 192.168.1.4 80-tcp,8080-8090-tcp
                  Example 2: scans new generic fromscanid 4
      
      - custom-nmap - Fully customized nmap scan. The user needs to provide the target and the raw
                      nmap flags.
                      Example: scans new custom-nmap 192.168.2.0/24 "-sSV -p-"
      """
SCANS_HELP_LIST = """
  - \033[1mscans list [running | done | <id> | <csv_id_range>]\033[0m
      Shows status information existing Scans. If no subcommand is specified, details for every Scan 
      will be printed. The details include the status of the scan, completion percentage and
      associated Rules, SourceNetworks and Targets, if any.
      
      By providing subcommands, it is possible to limit results to those scans that are currently
      running, or finished ('done'). Comma-separeted single Scan IDs or ranges can be provided to
      filter out the results.

      Example: 'scans list running 1-3,5' will print Scans with IDs 1, 2, 3 and 5."""
SCANS_HELP_PRINT = """
  - \033[1mscans print <scan_id>\033[0m
      Prints the results for a given Scan ID (which can be obtained from 'scans list').

      Note that the Scan needs to be finished before the results can be printed.
      
      Example: 'scans print 2' will print the results for the Scan with ID 2."""
SCANS_HELP_EXPORT = """
  - \033[1mscans export <scan_id> <filename>\033[0m
      Writes the results for a given Scan ID into disk. The output format will be defined by the 
      provided extension.

      Several formats are available:
        - .txt - plaintext. This is also the default if no extension is specified.
        - .md - Markdown
        - .json - JSON
        - .xml - nmap XML output
        - .html - HTML obtained from applying the nmap XSL to the XML output
      
      Example: 'scans export 3 json' will write results for the Scan with ID 3 in JSON format."""
SCANS_HELP_KILL = """
  - \033[1mscans kill <scan_id>\033[0m
      Sends KILL -15 to the background nmap process, updates the associated Scan accordingly.

      This call is asynchronous. The nmap run will return the failed status via its callback,
      and an error message will be shown to the user indicating that the scan failed.

      Example: 'scans kill 3' will kill the Scan with ID 3."""
SCANS_HELP_RM = """
  - \033[1mscans rm <scan_id>\033[0m
      Removes the Scan entry corresponding to the provided Scan ID. Note that currently-running
      scans cannot be removed (they need to be killed first). 

      Example: 'scans rm 4' will remove the Scan with ID 4."""
SCANS_HELP_CLEAN = """
   - \033[1mscans clean\033[0m
      Removes every Scan entry with status other than done or running.

      During usage of this tool, it might be the case that Scans fail (due to the 'kill' subcommand
      or other reasons), or are stuck in the running state (e.g. if the tool is forcefully killed).
      This command allows to keep the Scan list with just meaningful Scans."""
SCANS_HELP = f"""The 'scans' command manages Scans, which are mainly wrappers around background nmap runs.

Several subcommands are available:
{SCANS_HELP_NEW}
{SCANS_HELP_LIST}
{SCANS_HELP_PRINT}
{SCANS_HELP_EXPORT}
{SCANS_HELP_KILL}
{SCANS_HELP_RM}
{SCANS_HELP_CLEAN}
"""

RULES_SUBCOMMANDS = ["rm", "list", "hide", "unhide"]
RULES_LIST_SUBCOMMANDS = ["hidden", "all"]
RULES_HELP_LIST = """
  - \033[1mrules list [all | hidden | applicable | <rule_id> | <csv_rule_id_range> 
                        | zone=<zone_name> | <ip_range> | <csv_port_range> ]\033[0m
      Lists Rules entries. This is the main command to be used for firewall policy analysis.

      If no subcommand is provided, every rule (except those hidden) will be displayed.

      The following subcommands are available for filtering:

      - all - default behavior, equivalent to no subcommand.

      - hidden - show only those Rules that were marked as hidden.

      - applicable - show only those Rules that apply to the IP address of this machine's 
                       network interface (thus, filtering on source IP addresses).
        
      - <rule_id> - show only the Rule with the ID specified.
                    Example: rules list 3
        
      - <csv_rule_id_range> - show only the Rules matching the provided comma-separated list
                              of identifiers. Ranges can be provided as well.
                              Example: rules list 3,5-8
        
      - zone=<zone_name> - show only the Rules that match the provided zone, either in source
                           or destination.
                           Example: rules list zone=INSIDE
        
      - <ip_range> - shows ony the Rules that match any IP in the provided IP range, either
                     in source or destination.
                     Example: rules list 192.168.1.0/24
    
      - <csv_port_range> - shows only the Rules that match the provided comma-separated list
                           of ports, in the form <port_range>-<tcp|udp>.
                           Example: rules list 80-tcp,2000-2300-udp"""
RULES_HELP_SHOW = """
  - \033[1mrules show <rule_id>\033[0m
      Show the Rule entry corresponding to the provided Rule ID. This view includes a description
      in nested form of the objects conforming the firewall rule source and destination (IPs and
      ports), useful to visualize the object hierarchy. 

      Example: 'rules show 5' will show the Rule with ID 5."""
RULES_HELP_RM = """
  - \033[1mrules rm <rule_id>\033[0m
      Removes the Rule entry corresponding to the provided Rule ID.

      Example: 'rules rm 4' will remove the Rule with ID 4."""
RULES_HELP_HIDE = """
  - \033[1mrules hide <rule_id>\033[0m
      Hides the Rule entry corresponding to the provided Rule ID. This means that it will not be listed
      by the 'rules list' command (if filters apply), the only exception being 'rules list hidden'.
      
      Example: 'rules hide 2' will hide the Rule with ID 2."""
RULES_HELP_UNHIDE = """
  - \033[1mrules unhide <rule_id>\033[0m
      Removes the hidden status for the Rule entry corresponding to the provided Rule ID. This means that
      it will again be listed by the 'rules list' command (if filters apply).
      
      Example: 'rules unhide 2' will remove the hidden status to the Rule with ID 2."""
RULES_HELP = f"""The 'rules' command manages Rules, which are objects representing entries in a firewall
list of policies.

Note that, by design, these Rules need to be imported beforehand into this tool's database. Therefore,
there is no 'add' command. The reasoning behind is that every firewall firewall vendor has its nuances
in terms of exporting rules into a machine-readable format, and the transformations needed to be able
to import the rules in the format expected by this tool will vary.

Refer to the provided example import script in the 'ruleimporter' directory.

Several subcommands are available:
{RULES_HELP_LIST}
{RULES_HELP_SHOW}
{RULES_HELP_RM}
{RULES_HELP_HIDE}
{RULES_HELP_UNHIDE}
"""

SOURCENETWORKS_SUBCOMMANDS = ["add", "rm", "list"]
SOURCENETWORKS_HELP_ADD = """
   - \033[1msourcenetworks add <ip_range> "<name>"\033[0m
      Add a new SourceNetwork with the provided IP range and name.

      Example: sourcenetworks add 192.168.1.0/24 "My Home network" """
SOURCENETWORKS_HELP_RM = """
   - \033[1msourcenetworks rm <sourcenetwork_id>\033[0m
      Remove a given SourceNetwork as specified by the provided SourceNetwork ID.

      Example: 'sourcenetworks rm 2' will remove the SourceNetwork with ID 2."""
SOURCENETWORKS_HELP_LIST = """
   - \033[1msourcenetworks list\033[0m
      Will list the configured SourceNetworks, including the reference to any associated Scans."""
SOURCENETWORKS_HELP = f"""The 'sourcenetworks' command manages SourceNetworks, which are simply source IP ranges
to be taken into account in the manual analysis of network Rules and Scan results.
{SOURCENETWORKS_HELP_ADD}
{SOURCENETWORKS_HELP_RM}
{SOURCENETWORKS_HELP_LIST}
"""

TARGETS_SUBCOMMANDS = ["add", "rm", "list"]
TARGETS_HELP_ADD = """
   - \033[1mtargets add <ip_range> "<name>"\033[0m
      Add a new Target with the provided IP range and name.

      Example: targets add 172.16.1.0/24 "My Target network" """
TARGETS_HELP_RM = """
   - \033[1mtargets rm <target_id>\033[0m
      Remove a given Target as specified by the provided Target ID.

      Example: 'targets rm 2' will remove the Target with ID 2."""
TARGETS_HELP_LIST = """
   - \033[1mtargets list\033[0m
      Will list the configured Targets, including the reference to any associated Scans."""
TARGETS_HELP = f"""The 'targets' command manages Targets, which are simply target IP ranges
to be taken into account in the manual analysis of network Rules and Scan results.

Ideally, these Targets are also under our control, so that we can verify if any sort of
traffic originating from our scans is reaching them.
{TARGETS_HELP_ADD}
{TARGETS_HELP_RM}
{TARGETS_HELP_LIST}
"""

global repl

BANNER = """Welcome to network-tool.
Type 'help' to obtain available commands, 'exit' to close the tool.
"""

repl = Riposte(prompt="[network-tool] ", banner=BANNER)

@repl.command("exit")
def exit():
    exit = scans.kill_all_scans()
    if exit:
        sys.exit(0)

@repl.command("help")
def help(str1: str = None, str2: str = None):
    if str1 == "scans":
        if not str2:
            print(SCANS_HELP)
        if str2 == "new":
            print(SCANS_HELP_NEW)
        elif str2 == "list":
            print(SCANS_HELP_LIST)
        elif str2 == "print":
            print(SCANS_HELP_PRINT)
        elif str2 == "export":
            print(SCANS_HELP_EXPORT)
        elif str2 == "kill":
            print(SCANS_HELP_KILL)
        elif str2 == "rm":
            print(SCANS_HELP_RM)
        elif str2 == "clean":
            print(SCANS_HELP_CLEAN)
    elif str1 == "rules":
        if not str2:
            print(RULES_HELP)
        elif str2 == "list":
            print(RULES_HELP_LIST)
        elif str2 == "show":
            print(RULES_HELP_SHOW)
        elif str2 == "rm":
            print(RULES_HELP_RM)
        elif str2 == "hide":
            print(RULES_HELP_HIDE)
        elif str2 == "unhide":
            print(RULES_HELP_UNHIDE)
    elif str1 == "targets":
        if not str2:
            print(TARGETS_HELP)
        elif str2 == "add":
            print(TARGETS_HELP_ADD)
        elif str2 == "rm":
            print(TARGETS_HELP_RM)
        elif str2 == "list":
            print(TARGETS_HELP_LIST)
    elif str1 == "sourcenetworks":
        if not str2:
            print(SOURCENETWORKS_HELP)
        elif str2 == "add":
            print(SOURCENETWORKS_HELP_ADD)
        elif str2 == "rm":
            print(SOURCENETWORKS_HELP_RM)
        elif str2 == "list":
            print(SOURCENETWORKS_HELP_LIST)
    else:
        print_info(f"[i] Available commands: {", ".join(COMMANDS)}.")
        print_info("[i] Execute 'help <command>' for additional details.")
        print_info("[i] Tip: autocomplete (tab-based), command history (up/down arrows), and history search (Control-R) are available.")

@repl.complete("help")
def start_completer(text, line, start_index, end_index):
    if len(line.split(" ")) > 2:
        return []
    return [
        subcommand
        for subcommand in COMMANDS
        if subcommand.startswith(text)
    ]

@repl.command("scans", description="Execute scans per category.")
def scans_command(str1: str = None, str2: str = None, str3: str = None, str4: str = None):
    help_str = f"Usage: scans ({" | ".join(SCANS_SUBCOMMANDS)}). Execute 'help scans' for additional details." 
    help_new_str = f"""Usage: scans new ({" | ".join(SCANS_NEW_SUBCOMMANDS)}). 
    Each type works differently. Execute 'help scans new' for additional details."""
    help_kill_str = f"Usage: scans kill <scan_id>. Execute 'help scans kill' for additional details."
    help_rm_str = f"Usage: scans rm <scan_id>. Execute 'help scans rm' for additional details."
    help_show_str = f"Usage: scans show <scan_id>. Execute 'help scans show' for additional details."
    help_export_str = f"Usage: scans export <scan_id> <filename>. Execute 'help scans export' for additional details."

    if str1 == "new":
        target = str3
        if str2 == "recon":
            scans.recon_scan(target)
        elif str2 == "serviceid":
            if str3 == "fromscanid":
                scanid = parse_int(str4)
                if scanid:
                    scans.serviceid_scan(scanid=scanid)
            else:
                ports = str4
                scans.serviceid_scan(target, ports)
        elif str2 == "segmentation-check":
            scans.segmentation_check_scan(target)
        elif str2 == "generic":
            if str3 == "fromscanid":
                scanid = parse_int(str4)
                if scanid:
                    scans.generic_scan(scanid=scanid)
            else:
                ports = str4
                scans.generic_scan(target, ports)
        elif str2 == "custom-nmap":
            flags = str4
            scans.nmap_custom_scan(target, flags)
        else:
            repl.error("Incomplete 'scans new' command.")
            repl.info(help_new_str)
    elif str1 == "kill":
        scanid = parse_int(str2, error_msg=help_kill_str)
        if scanid:
            scans.kill_scan(scanid)
    elif str1 == "rm":
        scanid = parse_int(str2, error_msg=help_rm_str)
        if scanid:
            scans.rm_scan(scanid)
    elif str1 == "list":
        scans.list_scans(filter=str2)
    elif str1 == "show":
        scanid = parse_int(str2, error_msg=help_show_str)
        if scanid:
            scans.print_scan(scanid)
    elif str1 == "clean":
        scans.clean_scans()
    elif str1 == "export":
        scanid = parse_int(str2, error_msg=help_export_str)
        if scanid:
            output_file = str3
            scans.export_scan(scanid, output_file)
    else:
        repl.error("Unknown scan option.")
        repl.info(help_str)

@repl.complete("scans")
def start_completer(text, line, start_index, end_index):
    if line.startswith("scans new"):
        if len(line.split(" ")) > 3:
            return []
        if text == "new":
            return SCANS_NEW_SUBCOMMANDS
        return [
            subcommand
            for subcommand in SCANS_NEW_SUBCOMMANDS
            if subcommand.startswith(text)
        ]
    
    if len(line.split(" ")) > 2:
        return []
    return [
        subcommand
        for subcommand in SCANS_SUBCOMMANDS
        if subcommand.startswith(text)
    ]

@repl.command("sourcenetworks", description="Manage SourceNetworks.")
def sourcenetworks_command(str1: str, str2: str = None, str3 = None):
    help_str = f"Usage: sourcenetworks ({" | ".join(SOURCENETWORKS_SUBCOMMANDS)}). Execute 'help sourcenetworks' for additional details."
    help_add_str = f"Usage: sourcenetworks add <ip_range> \"<name>\". Execute 'help sourcenetworks add' for additional details."
    help_rm_str = f"Usage: sourcenetworks rm <sourcenetwork_id>. Execute 'help sourcenetworks rm' for additional details."

    if str1 == "add":
        if str2 and str3:
            sourcenetworks.add_sourcenetwork(ip_range=str2, name=str3)
        else:
            repl.info(help_add_str)
    elif str1 == "rm":
        snid = parse_int(str2, error_msg=help_rm_str)
        if snid:
            sourcenetworks.rm_sourcenetwork(snid)
    elif str1 == "list":
        sourcenetworks.list_sourcenetworks()
    else:
        repl.error("Unknown sourcenetworks option.")
        repl.info(help_str)

@repl.complete("sourcenetworks")
def start_completer(text, line, start_index, end_index):
    if len(line.split(" ")) > 2:
        return []
    return [
        subcommand
        for subcommand in SOURCENETWORKS_SUBCOMMANDS
        if subcommand.startswith(text)
    ]

@repl.command("targets", description="Manage Targets.")
def targets_command(str1: str, str2: str = None, str3 = None, str4 = None):
    help_str = f"Usage: targets {"/".join(TARGETS_SUBCOMMANDS)}. Execute 'help targets' for additional details."
    help_add_str = f"Usage: targets add <ip_range> <ports_csv> \"<name>\". Execute 'help targets add' for additional details."
    help_rm_str = f"Usage: targets rm <target_id>. Execute 'help targets rm' for additional details."

    if str1 == "add":
        if str2 and str3 and str4:
            targets.add_target(ip_range=str2, ports=str3, name=str4)
        else:
            repl.info(help_add_str)
    elif str1 == "rm":
        targetid = parse_int(str2, error_msg=help_rm_str)
        if targetid:
            targets.rm_target(targetid)
    elif str1 == "list":
        targets.list_targets()
    else:
        repl.error("Unknown targets option.")
        repl.info(help_str)

@repl.complete("targets")
def start_completer(text, line, start_index, end_index):
    if len(line.split(" ")) > 2:
        return []
    return [
        subcommand
        for subcommand in TARGETS_SUBCOMMANDS
        if subcommand.startswith(text)
    ]

@repl.command("rules", description="Manage Rules.")
def rules_command(str1: str, str2: str = None, str3 = None, str4 = None):
    help_str = f"Usage: rules {"/".join(RULES_SUBCOMMANDS)}. Execute 'help rules' for additional details."
    help_show_str = f"Usage: rules show <rule_id>. Execute 'help rules show' for additional details."
    help_rm_str = f"Usage: rules rm <rule_id>. Execute 'help rules rm' for additional details."
    help_hide_str = f"Usage: rules hide <rule_id>. Execute 'help rules hide' for additional details."
    help_unhide_str = f"Usage: rules unhide <rule_id>. Execute 'help rules unhide' for additional details."

    if str1 == "list":
        rules.list_rules(filter=str2)
    elif str1 == "show":
        ruleid = parse_int(str2, error_msg=help_show_str)
        if ruleid:
            rules.show_rule(ruleid)
    elif str1 == "rm":
        ruleid = parse_int(str2, error_msg=help_rm_str)
        if ruleid:
            rules.rm_rule(ruleid)
    elif str1 == "hide":
        ruleid = parse_int(str2, error_msg=help_hide_str)
        if ruleid:
            rules.hide_rule(ruleid)
    elif str1 == "unhide":
        ruleid = parse_int(str2, error_msg=help_unhide_str)
        if ruleid:
            rules.unhide_rule(ruleid)
    else:
        repl.error("Unknown rules option.")
        repl.info(help_str)

@repl.complete("rules")
def start_completer(text, line, start_index, end_index):
    if line.startswith("rules list"):
        if len(line.split(" ")) > 3:
            return []
        if text == "list":
            return RULES_LIST_SUBCOMMANDS
        return [
            subcommand
            for subcommand in RULES_LIST_SUBCOMMANDS
            if subcommand.startswith(text)
        ]
    if len(line.split(" ")) > 2:
        return []
    return [
        subcommand
        for subcommand in RULES_SUBCOMMANDS
        if subcommand.startswith(text)
    ]

def parse_int(value, error_msg="Please provide a valid identifier."):
    try:
        return int(value)
    except Exception:
        print(error_msg)
    return None

def print(msg):
    repl.print(msg)

def print_success(msg):
    repl.print(Palette.GREEN.format(msg))

def print_error(msg):
    repl.print(Palette.RED.format(msg))

def print_warn(msg):
    repl.print(Palette.YELLOW.format(msg))

def print_info(msg):
    repl.print(Palette.CYAN.format(msg))