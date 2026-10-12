"""Small upstream fixtures independent of the checked-in full snapshots."""

XML_NS = 'xmlns="http://www.iana.org/assignments"'
RAW = {
    "iana.active-roots": "# Version 2026101200, Last Updated fixture UTC\nCK\nCOM\nUK\n",
    "iana.root-database": '<table id="tld-table"><tr><td><a href="/domains/root/db/ck.html">.ck</a></td><td>country-code</td><td>CK registry</td></tr><tr><td><a href="/domains/root/db/com.html">.com</a></td><td>generic</td><td>COM registry</td></tr><tr><td><a href="/domains/root/db/uk.html">.uk</a></td><td>country-code</td><td>UK registry</td></tr></table>',
    "psl.list": "// VERSION: fixture-v1\n// ===BEGIN ICANN DOMAINS===\ncom\nuk\nco.uk\n*.ck\n!www.ck\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\nblogspot.com\n// ===END PRIVATE DOMAINS===\n",
    "iana.special-use.csv": "Name,Reference\nexample.com.,[RFC6761]\nonion.,[RFC7686]\n",
    "iana.special-use.xml": f'<registry {XML_NS} id="special-use-domain-names"><updated>2026-10-12</updated><registry id="special-use-domain"><note>Applies to listed domains and subdomains.</note><record><name>example.com.</name><xref type="rfc" data="rfc6761"/></record><record><name>onion.</name><xref type="rfc" data="rfc7686"/></record></registry></registry>',
    "icann.gtlds": '{"version":2,"updatedOn":"2026-10-12T00:00:00Z","gTLDs":[{"gTLD":"com","registryOperator":"COM registry","specification13":false,"contractTerminated":false}]}',
    "icann.reserved-names": f'<registry {XML_NS} id="reservedNames"><updated>2020-02-18</updated><registry id="IOC"><title>IOC</title><description>Second level; exceptions apply</description><xref type="uri" data="https://www.icann.org/policy"/><record><name>olympic</name><label1>olympic</label1><label2/></record></registry></registry>',
}
