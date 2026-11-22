"""Command-line entry points for the network workbench."""
import json
import signal
import sys
from threading import Event

from .network_export import export_network, project_network
from .packet_dissect import MAX_FRAMES, dissect_capture
from .packets import analyze_capture
from .workstation import read_bounded


def add_parser(commands):
    network = commands.add_parser("network", help="Protocol timeline, device evidence, diagnostics and monitoring")
    actions = network.add_subparsers(dest="network_action", required=True)
    for action, help_text in (
        ("timeline", "Analyze a local PCAP or PCAPNG"),
        ("device", "Read a local Cisco IOS command transcript"),
        ("compare", "Compare two local Cisco IOS transcripts"),
        ("diagnose", "Read local configuration and run explicitly authorized diagnostics"),
        ("monitor", "Repeat an authorized diagnostic plan for a finite period"),
        ("dissect", "Read typed frame metadata with an existing local TShark"),
    ):
        sub = actions.add_parser(action, help=help_text)
        sub.add_argument("--out", help="New directory for the HTML, JSON and CSV report")
        sub.add_argument("--include-identifiers", action="store_true", help="Retain identifiers in this export")
        if action in ("timeline", "device", "dissect"):
            sub.add_argument("--input", required=True, help="Existing local evidence file")
        if action == "compare":
            sub.add_argument("before")
            sub.add_argument("after")
        if action == "dissect":
            sub.add_argument("--tshark", help="Absolute path to an already available TShark executable")
            sub.add_argument("--limit", type=int, default=MAX_FRAMES)
        if action in ("diagnose", "monitor"):
            sub.add_argument("--interface")
            sub.add_argument("--source", help="Numeric source address on the selected interface")
            sub.add_argument("--gateway", help="Explicit numeric gateway")
            sub.add_argument("--peer", action="append", default=[])
            sub.add_argument("--trace", help="Explicit numeric destination")
            sub.add_argument("--dns", help="Explicit numeric DNS server")
            sub.add_argument("--application", help="Explicit HTTP(S) URL for a bounded HEAD check")
            sub.add_argument("--doh", help="Explicit HTTPS DNS-over-HTTPS endpoint")
            sub.add_argument("--ntp", help="Explicit numeric NTP server")
            sub.add_argument("--timeout", type=float, default=2.0)
            sub.add_argument("--max-hops", type=int, default=12)
            sub.add_argument("--samples", type=int, default=5 if action == "monitor" else 1)
            sub.add_argument("--interval", type=float, default=1.0)
            sub.add_argument("--failure-threshold", type=int, default=2)
            sub.add_argument("--preview", action="store_true", help="Validate and display the exact plan without collecting")
            sub.add_argument("--authorized", action="store_true", help="Confirm permission for the explicit endpoints")


def _plan_options(args):
    return {"interface": args.interface, "source": args.source, "gateway": args.gateway, "peers": args.peer,
                "dns": args.dns, "trace": args.trace, "application": args.application, "ntp": args.ntp, "doh": args.doh,
                "timeout": args.timeout, "max_hops": args.max_hops, "samples": args.samples,
                "interval": args.interval, "failure_threshold": args.failure_threshold}


def run(args):
    action = args.network_action
    if action == "timeline":
        report = analyze_capture(read_bounded(args.input))
    elif action == "dissect":
        report = dissect_capture(args.input, executable=args.tshark, limit=args.limit)
    elif action in ("device", "compare"):
        from .network_devices import compare_device_evidence, read_device_evidence
        if action == "device":
            report = read_device_evidence(args.input)
        else:
            report = compare_device_evidence(read_device_evidence(args.before), read_device_evidence(args.after))
    else:
        from .network_diagnostics import (
            diagnose_network,
            diagnostic_plan,
            monitor_network,
        )
        options = _plan_options(args)
        if args.preview:
            report = {"kind": "network-plan", "plan": diagnostic_plan(**options)}
        else:
            function = monitor_network if action == "monitor" else diagnose_network
            stop = Event()
            previous = signal.signal(signal.SIGINT, lambda *_: stop.set())
            try:
                report = function(authorized=args.authorized, cancel=stop, **options)
            finally:
                signal.signal(signal.SIGINT, previous)
    if args.out:
        print(export_network(report, args.out, args.include_identifiers)["html"])
    else:
        json.dump(project_network(report, args.include_identifiers), sys.stdout, ensure_ascii=True,
                  indent=2, allow_nan=False)
        print()
    status = report.get("status")
    return 130 if status == "cancelled" else 1 if status == "partial" else 0
