# Selected Responsible Vulnerability Disclosure Work

This page summarizes selected vulnerability research and reporting activity. It describes the methodology and reporting context without identifying potentially affected systems or disclosing sensitive technical details.

## 1. Exposure of Government Procurement Documentation

- **Discovery approach:** Passive reconnaissance and open-source intelligence (OSINT).
- **Finding:** Confidential government procurement documentation was accessible through a publicly exposed government-associated web domain.
- **Reporting:** The exposure was reported through a responsible vulnerability disclosure process.
- **Acknowledgement:** The report was acknowledged by the National Critical Information Infrastructure Protection Centre (NCIIPC).

## 2. Anonymous FTP Access-Control Misconfiguration

- **Discovery approach:** Service enumeration, banner analysis, and protocol-level configuration checks.
- **Finding:** Anonymous FTP access was enabled on multiple government-associated hosts, allowing unauthenticated access to the service.
- **Validation:** Controlled, read-only checks were used to validate the configuration; the work did not involve modifying data.
- **Reporting:** A technical proof of concept was submitted under responsible disclosure guidelines.

## Responsible Testing Practices

- Used passive reconnaissance where appropriate and kept validation controlled and read-only.
- Avoided destructive testing, data modification, and unnecessary access to sensitive information.
- Prepared technical findings to help responsible parties understand and assess the reported exposure.

## Scope and Verification

This page reflects selected disclosure examples recorded in my resume. It does not state a total number of reports. Public target hostnames, IP addresses, sensitive evidence, and additional technical details are intentionally omitted. Additional entries can be added when the report details and disclosure status are verified and safe to publish.
