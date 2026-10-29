"""Dedicated offline survey CLI; shared report privacy and exclusive output."""


def add_parser(commands):
    sub = commands.add_parser(
        "survey",
        help="Import selected-network samples and export a conservative local heatmap; no live collection",
    )
    sub.add_argument("--input", required=True)
    sub.add_argument("--format", required=True, choices=("json", "csv"))
    sub.add_argument("--grid-size", type=int, default=40)
    sub.add_argument("--radius", type=float, default=0.35)
    sub.add_argument("--power", type=float, default=2)
    sub.add_argument("--out")
    sub.add_argument("--include-identifiers", action="store_true")


def run(args):
    from .workstation import read_bounded
    from .survey import import_survey
    from .heatmap import interpolate_survey
    from .investigate import build_investigation

    data = import_survey(read_bounded(args.input), args.format)
    data = interpolate_survey(
        data, grid_size=args.grid_size, radius=args.radius, power=args.power
    )
    return build_investigation(dict(schema_version=1, wifi_survey=data))
