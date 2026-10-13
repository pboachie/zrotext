"""Experimental native sealed-content companion; not live delivery authority.

Protected custody requires a locally qualified Windows TPM. Other systems can
verify public evidence and explicitly use software test custody. No automatic
software fallback, backend grant, remote attestation or registry publication.
"""
from .sealed_candidate import SealedError, SoftwareRecipient
from .checkpoint_store import CheckpointStore
from .election_journal import ElectionJournal
from .cng_custody import CngUnavailable, HardwareRecipient, probe_platform
from .cng_signing import HardwareSigner
from .compose03 import Composition, SoftwareSigner, compose_outbound03
from .outbound_journal import OutboundJournal

__version__ = '0.1.0a1'
__all__ = ['SealedError', 'SoftwareRecipient', 'CheckpointStore', 'ElectionJournal',
           'CngUnavailable', 'HardwareRecipient', 'probe_platform', 'HardwareSigner',
           'Composition', 'SoftwareSigner', 'compose_outbound03', 'OutboundJournal']
