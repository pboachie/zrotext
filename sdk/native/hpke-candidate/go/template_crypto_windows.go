//go:build windows

package hpke

func OpenProtectedEncryptedTemplate(m *Manifest, s EncryptedTemplateScope, now uint64, recipient *HardwareRecipient, envelope []byte) (*TemplateContent, error) {
	if recipient == nil {
		return nil, ErrProtectedUnavailable
	}
	return openTemplate(m, s, now, envelope, recipient.openContent)
}

func OpenCurrentProtectedEncryptedTemplate(source TemplateAuthoritySource, s EncryptedTemplateScope, recipient *HardwareRecipient, envelope []byte) (*TemplateContent, error) {
	if recipient == nil {
		return nil, ErrProtectedUnavailable
	}
	return openCurrentTemplate(source, s, envelope, recipient.openContent)
}
