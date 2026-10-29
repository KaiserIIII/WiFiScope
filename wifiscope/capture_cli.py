"""Capture CLI registration; local operational interface labels are explicit."""


def add_parser(commands):
    sub = commands.add_parser(
        "capture",
        help="Bounded local live metadata capture; explicit interface and authorization required",
    )
    sub.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Read-only local operational interface names (not report export)",
    )
    sub.add_argument("--interface")
    sub.add_argument("--authorized", action="store_true")
    sub.add_argument("--duration", type=float, default=10)
    sub.add_argument("--max-packets", type=int, default=2000)
    sub.add_argument("--max-bytes", type=int, default=8388608)
    sub.add_argument("--snaplen", type=int, default=96)
    sub.add_argument("--filter", default="")
    sub.add_argument("--promiscuous", action="store_true")
    sub.add_argument("--retain-packets", action="store_true")
    sub.add_argument("--raw-out")
    sub.add_argument("--out")
    sub.add_argument("--include-identifiers", action="store_true")


def run(args):
    from pathlib import Path
    from .live_capture import capture_live

    if args.out:
        report = Path(args.out)
        if report.exists() or report.is_symlink():
            raise ValueError(
                "Capture report requires a new output directory; existing paths are refused."
            )
        for parent in report.absolute().parents:
            if (parent.exists() or parent.is_symlink()) and not parent.is_dir():
                raise ValueError("Capture report ancestors must be directories.")
        try:
            report = report.resolve()
            raw = Path(args.raw_out).resolve() if args.raw_out else None
        except RuntimeError as error:
            raise ValueError("Capture output paths could not be resolved.") from error
        if raw is not None and (report == raw or raw in report.parents):
            raise ValueError(
                "The report directory cannot be the raw capture file or nested beneath it."
            )
    return capture_live(
        args.interface,
        duration=args.duration,
        max_packets=args.max_packets,
        max_bytes=args.max_bytes,
        snaplen=args.snaplen,
        packet_filter=args.filter,
        authorized=args.authorized,
        promiscuous=args.promiscuous,
        retain_packets=args.retain_packets,
        raw_path=args.raw_out,
    )


def list_interfaces(args):
    from .live_capture import list_capture_interfaces

    if (
        args.interface
        or args.raw_out
        or args.out
        or args.authorized
        or args.promiscuous
        or args.retain_packets
        or args.filter
        or args.duration != 10
        or args.max_packets != 2000
        or args.max_bytes != 8388608
        or args.snaplen != 96
    ):
        raise ValueError(
            "Interface listing is read-only; use a separate capture command for capture options."
        )
    return list_capture_interfaces()
