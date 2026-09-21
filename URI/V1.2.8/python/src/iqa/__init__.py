"""iqa -- reference implementation of the IQA attestation layer (RFC-009 sec. 10/sec. 11).

What is in the box
------------------
* :mod:`iqa.iqa_uri` -- the ``iqa://`` URI codec: validate, canonicalise,
  classify (hash vs name subject), enforce the two **closed sets**
  (``organ`` / ``action``), report sec. 11.3 action safety classes, and derive
  ``IQA_ROUTE`` (SPEC/IQA-URI-ATTEST-v1.2.6 sec. 3).
* :mod:`iqa.attest` -- the sovereign **attestation envelope** (Ed25519,
  self-certifying, domain prefix ``iqa-attest-v1``). Optional dependency.
* :mod:`iqa.vectors` -- the published conformance vectors, shipped inside the
  wheel so the self-test works from an installed package with no repository
  checkout.

Scope
-----
This is the **codec**, not the organism. Staking, vitality monitoring and the
post-quantum Lattice Guard are RFC-009 narrative with no object here -- see the
package README's scope table and SPEC sec. 8.

Verify it
---------
    $ python -m iqa.selftest
    [PASS] all N checks passed

Offline. No account. No network. ``[PASS]`` or it is not.
"""

from . import iqa_uri
from .iqa_uri import (
    ACTIONS,
    HASH_LENGTHS,
    ORGANS,
    SAFE_ACTIONS,
    SCHEME,
    STANDINGS,
    UNSAFE_ACTIONS,
    IqaUriError,
    derive_route,
    derive_route_hex,
    is_valid_action,
    parse,
)

__version__ = "1.2.8"

__all__ = [
    "__version__",
    "iqa_uri",
    "SCHEME",
    "ORGANS",
    "ACTIONS",
    "STANDINGS",
    "HASH_LENGTHS",
    "SAFE_ACTIONS",
    "UNSAFE_ACTIONS",
    "IqaUriError",
    "parse",
    "derive_route",
    "derive_route_hex",
    "is_valid_action",
]
