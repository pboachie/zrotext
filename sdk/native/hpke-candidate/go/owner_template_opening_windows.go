//go:build windows

package hpke

import "context"

// OpenLatestProtected requires the native qualified PCP recipient. Its owner
// retains responsibility for Close/Delete; this lifecycle never destroys keys.
func (o *OwnerTemplateOpening) OpenLatestProtected(ctx context.Context, recipient *HardwareRecipient) (*TemplateOpenedPreview, error) {
	if recipient == nil {
		return nil, ErrProtectedUnavailable
	}
	return o.open(ctx, recipient.PublicPoint, func(m *Manifest, s EncryptedTemplateScope, now uint64, wire []byte) (*TemplateContent, error) {
		return OpenProtectedEncryptedTemplate(m, s, now, recipient, wire)
	}, nil)
}
