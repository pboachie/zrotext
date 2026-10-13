"""Experimental native sealed-content companion; not live delivery authority.

Protected custody requires a locally qualified Windows TPM. Other systems can
verify public evidence and explicitly use software test custody. No automatic
software fallback, backend grant, remote attestation or registry publication.
"""
from .sealed_candidate import SealedError, SoftwareRecipient, verify_manifest03_current
from .checkpoint_store import CheckpointStore
from .election_journal import ElectionJournal
from .cng_custody import CngUnavailable, HardwareRecipient, probe_platform
from .cng_signing import HardwareSigner
from .compose03 import Composition, SoftwareSigner, compose_outbound03
from .outbound_journal import OutboundJournal
from .compose02 import SealedEnvelopeError, SEALED_CONTENT_TYPE, compose_outbound02
from .root_checkpoint import RootCheckpointStore
from .reply_selection import verify_archive_reply_selection02
from .outbound02_journal import OutboundJournal02
from .sealed_http import SealedHttpClient, SealedHttpError, PreparedSubmission
from .original_reply_client import OriginalReplyClient, OriginalReplyError
from .original_reply_reader import open_original_reply02
from .original_reply_checkpoint import OriginalReplyCheckpoint
from .encrypted_template import (TemplateError,canonical_template_bytes,template_digest,estimate_segments,
    preview_encrypted_template,encrypted_template_aad,seal_encrypted_template_bytes,open_encrypted_template_bytes,
    seal_encrypted_template,open_encrypted_template,encrypted_template_digest)

__version__ = '0.1.0a1'
__all__ = ['SealedError', 'SoftwareRecipient', 'CheckpointStore', 'ElectionJournal',
           'CngUnavailable', 'HardwareRecipient', 'probe_platform', 'HardwareSigner',
           'Composition', 'SoftwareSigner', 'compose_outbound03', 'OutboundJournal',
           'SealedEnvelopeError', 'SEALED_CONTENT_TYPE', 'compose_outbound02', 'RootCheckpointStore',
           'verify_archive_reply_selection02', 'OutboundJournal02', 'verify_manifest03_current',
           'SealedHttpClient', 'SealedHttpError', 'PreparedSubmission',
           'OriginalReplyClient', 'OriginalReplyError', 'open_original_reply02', 'OriginalReplyCheckpoint',
           'TemplateError','canonical_template_bytes','template_digest','estimate_segments','preview_encrypted_template',
           'encrypted_template_aad','seal_encrypted_template_bytes','open_encrypted_template_bytes',
           'seal_encrypted_template','open_encrypted_template','encrypted_template_digest']

from .contact_integrity import (ContactIntegrityError,encode_contact_reader_statement01,parse_contact_reader_statement01,
    verify_contact_reader_statement01,encode_contact_field01,parse_contact_field01,verify_contact_field01,
    encode_contact_mutation01,parse_contact_mutation01,verify_contact_mutation01,verify_contact_transition01,
    contact_statement_identity,contact_field_identity,contact_mutation_identity,contact_transition_identity)
__all__ += ['ContactIntegrityError','encode_contact_reader_statement01','parse_contact_reader_statement01',
    'verify_contact_reader_statement01','encode_contact_field01','parse_contact_field01','verify_contact_field01',
    'encode_contact_mutation01','parse_contact_mutation01','verify_contact_mutation01','verify_contact_transition01',
    'contact_statement_identity','contact_field_identity','contact_mutation_identity','contact_transition_identity']

from .contact_history import ContactHistory, ContactHistoryError
__all__ += ['ContactHistory','ContactHistoryError']

from .contact_producer import (OwnerRootSigner,SoftwareOwnerRootSigner,ContactCancellation,
    ContactProducerError,HistoricalProduction,produce_contact_field01,produce_contact_transition01)
__all__ += ['OwnerRootSigner','SoftwareOwnerRootSigner','ContactCancellation','ContactProducerError',
    'HistoricalProduction','produce_contact_field01','produce_contact_transition01']

from .workflow_context import (WorkflowContextError,WorkflowContextCancellation,workflow_context_aad,
    seal_workflow_context,open_workflow_context,seal_integration_workflow_context,open_integration_workflow_context)
__all__ += ['WorkflowContextError','WorkflowContextCancellation','workflow_context_aad','seal_workflow_context',
    'open_workflow_context','seal_integration_workflow_context','open_integration_workflow_context']

from .sealed_lifecycle import SealedLifecycleClient,SealedLifecycleError,SEALED_MESSAGE_STATES
__all__ += ['SealedLifecycleClient','SealedLifecycleError','SEALED_MESSAGE_STATES']

from .template_store import TemplateStoreError,TemplateSaveRequest,template_save_request,template_save_receipt
__all__ += ['TemplateStoreError','TemplateSaveRequest','template_save_request','template_save_receipt']
from .owner_template import OwnerTemplateReader, OwnerTemplateError
from .owner_template_save import OwnerTemplateClient
from .owner_context import OwnerWorkflowContextClient, OwnerContextError

from .template_authoring import OwnerTemplateAuthoring,TemplateAuthoringError
__all__ += ['OwnerTemplateAuthoring','TemplateAuthoringError']

from .template_opening import OwnerTemplateOpening,TemplateOpeningError
__all__ += ['OwnerTemplateOpening','TemplateOpeningError']

from .conversation_proposals import (ConversationProposalError,verify_phone_key_export02,verify_archive_public_header02,
    encode_conversation_genesis_proposal02,encode_conversation_activation_proposal02,encode_conversation_refresh_proposal02)
__all__ += ['ConversationProposalError','verify_phone_key_export02','verify_archive_public_header02',
    'encode_conversation_genesis_proposal02','encode_conversation_activation_proposal02','encode_conversation_refresh_proposal02']

from .genesis_ceremony import ConversationGenesis,GenesisCeremonyError,GenesisRootSigner,SoftwareGenesisRootSigner
__all__ += ['ConversationGenesis','GenesisCeremonyError','GenesisRootSigner','SoftwareGenesisRootSigner']
