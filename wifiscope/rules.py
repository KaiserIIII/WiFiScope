"""Controlled investigation prose; imported descriptions never become templates."""
RULES = {
    'packet-http': ('Plaintext HTTP request observed in capture', 'Review whether the observed HTTP traffic should use encryption. Metadata alone does not establish disclosure of credentials.', 'Review a new authorized offline capture for the same application and scope; capture gaps cannot establish resolution.'),
    'arp-conflict': ('Conflicting ARP bindings need review', 'Review conflicting IP-to-MAC observations with the network owner; high availability, proxy ARP and address reuse may explain them. This is not confirmed interception.', 'Compare authorized observations with the intended ARP and high availability configuration.'),
    'cleartext-exposure': ('Cleartext service exposure', 'Review whether the endpoint intentionally provides a potentially cleartext protocol; a port number is only an identification hint.', 'Repeat the authorized endpoint check and verify the application protocol and encryption policy.'),
    'management-exposure': ('Management or file-sharing exposure', 'Review authorized clients and administrative scope; an open management port does not establish a vulnerability.', 'Repeat the authorized endpoint check from the intended client scope and review access policy.'),
    'tls-trust': ('Certificate trust verification failed', 'Review certificate chain, hostname, local clock and local trust store; a local verification failure does not establish its cause.', 'Repeat normal certificate verification with a checked clock and trust store; do not disable verification.'),
    'tls-expired': ('Certificate expired', 'Renew the certificate and verify the observed clock and certificate validity period.', 'Repeat verified TLS negotiation after renewal and check the expiry evidence.'),
    'tls-expiring': ('Certificate expires within 30 days', 'Schedule certificate renewal and verify the observed validity period.', 'Repeat verified TLS negotiation and check the replacement certificate expiry.'),
    'tls-legacy': ('Legacy TLS version observed', 'Review support for the explicitly observed legacy TLS version; this check does not enumerate all supported versions.', 'Repeat the authorized normal TLS negotiation and review server protocol configuration.'),
    'tls-weak-cipher': ('Weak negotiated cipher observed', 'Review the explicitly observed weak cipher with the service owner.', 'Repeat normal TLS negotiation after configuration review; no downgrade scan is required.'),
    'http-transport': ('HTTP transport observed', 'Review whether this endpoint should use HTTPS; HTTP alone does not prove that credentials were exposed.', 'Repeat the authorized endpoint HEAD check and verify the intended transport policy.'),
    'http-hsts': ('HTTPS HSTS policy needs review', 'Review a positive HSTS max-age policy for this successful HTTPS endpoint.', 'Repeat the successful HTTPS HEAD request and review the HSTS check.'),
    'http-csp': ('HTML content security policy absent', 'Review an appropriate content security policy for this observed HTML endpoint.', 'Repeat the successful HTML HEAD request and review the CSP check.'),
    'http-frame': ('HTML frame protection needs review', 'Review restrictive frame-ancestors or frame protection for this observed HTML endpoint.', 'Repeat the successful HTML HEAD request and review frame protection.'),
    'http-nosniff': ('HTML MIME protection absent', 'Review X-Content-Type-Options nosniff for this observed HTML endpoint.', 'Repeat the successful HTML HEAD request and review the nosniff check.'),
    'cookie-secure': ('Observed cookie lacks Secure flag', 'Review the Secure flag for observed cookies; cookie values are not retained.', 'Repeat the successful endpoint check and inspect the aggregate cookie flag result.'),
    'cookie-httponly': ('Observed cookie lacks HttpOnly flag', 'Review whether observed cookies require HttpOnly; cookie values are not retained.', 'Repeat the successful endpoint check and inspect the aggregate cookie flag result.'),
    'family-reachability': ('IPv4 and IPv6 reachability differ', 'Review intended address-family policy; resolved addresses may represent different systems and this is not proof of a policy failure.', 'Repeat the same authorized scope across both address families and compare equivalent endpoints.'),
    'scanner-finding': ('Imported scanner finding', 'Review the original scanner result locally and independently validate its applicability before assigning a confirmed vulnerability.', 'Retest the same authorized scope using an appropriate scanner and verify the specific issue independently.'),
}


def catalog():
    from .audit import assess
    sample = dict(wifi=[dict(ssid='sample', authentication='Open', encryption='WEP', signal_percent=1),
                        dict(ssid='sample', authentication='WPA2', encryption='TKIP'), {}],
                  firewall=[dict(name='Public', enabled=False), {}])
    result = dict(RULES)
    for finding in assess(sample) + assess({}):
        result[finding['code']] = (finding['title'], finding['recommendation'],
                                  'Repeat the authorized local observation and compare equivalent scope; missing evidence cannot resolve a prior finding.')
    return result
