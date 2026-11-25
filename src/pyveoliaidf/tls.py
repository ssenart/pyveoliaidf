"""The TLS settings: the Veolia site does not send its intermediate certificate, so the library brings it."""

import ssl
from importlib import resources

import certifi

CERTIFICATE_PACKAGE = "pyveoliaidf.certs"

# The Gandi intermediates that can sign connexion.leaudiledefrance.fr, which the site leaves out of its chain. A renewal
# of the site certificate can change the issuer: GandiCert signs the one of November 2026, the other the older ones.
INTERMEDIATE_CERTIFICATES = ("gandicert.pem", "gandi_rsa_dv_ssl_ca_3.pem")


def build_ssl_context() -> ssl.SSLContext:
    """Returns a TLS context that trusts the usual authorities (certifi) and the missing intermediate certificates."""

    context = ssl.create_default_context(cafile=certifi.where())
    for name in INTERMEDIATE_CERTIFICATES:
        certificate = resources.files(CERTIFICATE_PACKAGE).joinpath(name).read_text(encoding="ascii")
        context.load_verify_locations(cadata=certificate)

    return context
