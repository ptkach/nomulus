# Nomulus

| Internal Build | FOSS Build | License | Code Search |
|:--------------:|:----------:|:-------:|:-----------:|
|[![Build Status for Google Registry internal build](https://storage.googleapis.com/domain-registry-kokoro/internal/build.svg)](https://storage.googleapis.com/domain-registry-kokoro/internal/index.html)|[![Build Status for the open source build](https://storage.googleapis.com/domain-registry-kokoro/foss/build.svg)](https://storage.googleapis.com/domain-registry-kokoro/foss/index.html)|[![License for this repo](https://img.shields.io/github/license/google/nomulus.svg)](https://github.com/google/nomulus/blob/master/LICENSE)|[![Link to Code Search](https://www.gstatic.com/devopsconsole/images/oss/favicons/oss-32x32.png)](https://cs.opensource.google/nomulus/nomulus)|

![Nomulus logo](./nomulus-logo.png)

## Overview

Nomulus is an open source, scalable, cloud-based service for operating
[top-level domains](https://en.wikipedia.org/wiki/Top-level_domain) (TLDs). It
is the authoritative source for the TLDs that it runs, meaning that it is
responsible for tracking domain name ownership and handling registrations,
renewals, availability checks, and WHOIS requests. End-user registrants (i.e.,
people or companies that want to register a domain name) use an intermediate
domain name registrar acting on their behalf to interact with the registry.

Nomulus runs on [Google Kubernetes Engine](https://cloud.google.com/kubernetes-engine)
and is written primarily in Java. It is the software that
[Google Registry](https://www.registry.google/) uses to operate TLDs such as .google,
.app, .how, .soy, and .みんな. It can run any number of TLDs in a single shared registry
system using horizontal scaling. Its source code is publicly available in this
repository under the [Apache 2.0 free and open source license](https://www.apache.org/licenses/LICENSE-2.0).

## Getting started

The following resources provide information on getting the code and setting up a
running system:

*   [Install
    guide](https://github.com/google/nomulus/blob/master/docs/install.md)
*   View the source code for the [Main HTTP server](https://github.com/google/nomulus/tree/master/core/src/main/java/google/registry)
    and for the [EPP proxy](https://github.com/google/nomulus/tree/master/proxy/src/main/java/google/registry)
*   [Other docs](https://github.com/google/nomulus/tree/master/docs)
*   [Javadoc](https://javadoc.nomulus.foo/)
*   [Nomulus discussion
    group](https://groups.google.com/forum/#!forum/nomulus-discuss), for any
    other questions

If you are thinking about running a production registry service using our
platform, please drop by the user group and introduce yourself and your use
case. To report issues or make contributions, use GitHub issues and pull
requests.

## Capabilities

Nomulus has the following capabilities:

*   **[Extensible Provisioning Protocol
    (EPP)](https://en.wikipedia.org/wiki/Extensible_Provisioning_Protocol)**: An
    XML protocol that is the standard format for communication between
    registrars and registries. It includes operations for registering, renewing,
    checking, updating, and transferring domain names.
*   **[DNS](https://en.wikipedia.org/wiki/Domain_Name_System) interface**: The
    registry provides a pluggable interface that can be implemented to handle
    different DNS providers. It includes a sample implementation using [Google
    Cloud DNS](https://cloud.google.com/dns/), as well as an RFC 2136 compliant
    implementation that works with BIND. If you are using Google Cloud DNS, you
    may need to understand its capabilities and provide your own
    multi-[AS](https://en.wikipedia.org/wiki/Autonomous_system_\(Internet\)) solution.
*   **[WHOIS](https://en.wikipedia.org/wiki/WHOIS)**: A text-based protocol that
    returns ownership and contact information on registered domain names.
*   **[Registration Data Access Protocol
    (RDAP)](https://en.wikipedia.org/wiki/Registration_Data_Access_Protocol)**:
    A JSON API that returns structured, machine-readable information about
    domain name ownership. It is essentially a newer version of WHOIS.
*   **[Registry Data Escrow (RDE)](https://icannwiki.com/Data_Escrow)**: A daily
    export of all ownership information for a TLD to a third party escrow
    provider to allow take-over by another registry operator in the event of
    serious failure. This is required by ICANN for all [new
    gTLDs](https://newgtlds.icann.org/).
*   **Premium pricing**: Communicates prices for premium domain names (i.e.,
    those that are highly desirable) and supports configurable premium
    registration and renewal prices. An extensible interface allows fully
    programmatic pricing.
*   **Billing history**: A full history of all billable events is recorded,
    suitable for ingestion into an invoicing system.
*   **Registration periods**: Qualified Launch Partner, Sunrise, Landrush,
    Claims, and General Availability periods of the standard gTLD lifecycle are
    all supported.
*   **Brand protection for trademark holders (via
    [TMCH](https://newgtlds.icann.org/en/about/trademark-clearinghouse/faqs))**:
    Allows rights-holders to protect their brands by blocking registration of
    domains using their trademark. This is required by ICANN for all new gTLDs.
*   **Registrar support console**: A self-service web console that registrars
    can use to manage their accounts in the registry system.
*   **Reporting**: Support for required external reporting (such as [ICANN
    monthly registry
    reports](https://www.icann.org/resources/pages/registry-reports),
    [CZDS](https://czds.icann.org/), Billing and Registration Activity) as well
    as internal reporting using [BigQuery](https://cloud.google.com/bigquery/).
*   **Administrative tool**: Performs the full range of administrative tasks
    needed to manage a running registry system, including creating and
    configuring new TLDs.
*   **Secure storage of cryptographic keys**: A keyring interface is
      provided for plugging in your own implementation (see [configuration
      doc](https://github.com/google/nomulus/blob/master/docs/configuration.md)
      for details), and an implementation based on
      [Google Cloud Secret Manager](https://cloud.google.com/security/products/secret-manager) is
      available.
*   **TPC Proxy**: Nomulus is built on top of the [Jetty](https://jetty.org/)
    container that implements the [Jakarta Servlet](https://jakarta.ee/specifications/servlet/)
    specification and only serves HTTP/S traffic. A proxy to translate raw TCP traffic (e.g., EPP)
    to and from HTTP is provided.
    Instructions on setting up the proxy
    are [available](https://github.com/google/nomulus/blob/master/docs/proxy-setup.md).
    The proxy can either run in a separate cluster and communicate to Nomulus public HTTP
    endpoints via the Internet, or as a sidecar with the Nomulus image in the same pod and
    communicate to it via loopback.

## Additional components

Registry operators interested in deploying Nomulus will likely require some
additional components that need to be configured separately.

*   A way to invoice registrars for domain name registrations and accept
    payments. Nomulus records the information required to generate invoices in
    [billing
    events](https://github.com/google/nomulus/blob/master/docs/code-structure.md#billing-events).
*   Fully automated reporting to meet ICANN's requirements for gTLDs. Nomulus
    includes substantial reporting functionality, but some additional work will
    be required by the operator in this area.

*   System status and uptime monitoring.

## Outside references

*   [Identity Digital](http://identity.digital) has helped review the code and
    provided valuable feedback.
*   [CoCCa](http://cocca.org.nz) and [FRED](https://fred.nic.cz) are other
    open-source registry platforms in use by many TLDs.
*   We are not aware of any fully open source domain registrar projects, but
    open source EPP Toolkits (not yet tested with Nomulus; may require
    integration work) include:
    *   [Universal Registry/Registrar Toolkit](https://sourceforge.net/projects/epp-rtk/)
    *   [ari-toolkit](https://github.com/AusRegistry/ari-toolkit)
    *   [Net::DRI](https://metacpan.org/pod/Net::DRI)
*   Some Open Source DNS Projects that may be useful, but which we have not
    tested:
    *   [AtomiaDNS](https://github.com/atomia/atomiadns)
    *   [PowerDNS](https://github.com/PowerDNS/pdns)
