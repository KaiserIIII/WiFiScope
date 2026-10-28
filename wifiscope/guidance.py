"""Small display-independent guided-action decisions, using the real validator."""
import ipaddress
from urllib.parse import urlsplit

from .probe import validate_request


ERRORS = {
    'invalidtarget': '请输入单个主机名或 IP（不填网段）；可选 URL 必须为同一主机的 HTTP/HTTPS 地址，不能含账号、查询或片段。',
    'authorization': '开始前请确认目标与端口，并勾选旁边的授权确认。',
    'noevidence': '尚无可导出的证据。请先选择离线演示、本机检查或导入文件。',
    'busy': '当前操作仍在进行；请等待完成或点击“取消当前操作”。',
    'fileformat': 'Invalid file format / 文件读取失败。请检查所选格式、16 MiB 大小限制和读取权限；可重新载入离线演示。',
    'privacycompare': '独立脱敏文件不能可靠合并或关联身份。请保持替换导入，或在专业工作台使用仅数量比较。',
    'export': '无法导出。请选择尚不存在的新目录名称，并检查父目录写入权限。',
    'unknown': 'Check input format / 操作未完成。请检查输入和权限，或加载离线演示后重试；上一份证据会保留。',
}


class GuidanceError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(ERRORS[code])


def target_plan(host, url=''):
    """Validate without IO; minimum_seconds is the legacy N/4 planning estimate."""
    try:
        hosts, ports, urls = validate_request([host.strip()], [80, 443], 1, .5, [url.strip()] if url.strip() else [])
        if len(hosts) != 1:
            raise ValueError
    except (ValueError, TypeError):
        raise GuidanceError('invalidtarget') from None
    endpoints = list(ports)
    tls = {443}
    for value in urls:
        parsed = urlsplit(value)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        if port not in endpoints:
            endpoints.append(port)
        if parsed.scheme == 'https':
            tls.add(port)
    count = len(endpoints) + len(tls) + len(urls)
    try:
        ipaddress.ip_address(hosts[0])
        max_addresses = 1
    except ValueError:
        max_addresses = 4
    return dict(hosts=hosts, ports=ports, urls=urls, endpoint_ports=endpoints, tls_ports=sorted(tls),
                connections_per_address=count, minimum_seconds=count / 4, max_addresses=max_addresses)
