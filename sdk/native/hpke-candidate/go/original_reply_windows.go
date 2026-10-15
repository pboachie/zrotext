package hpke

// OpenHardwareOriginalReply02 requires the qualified native protected recipient;
// it never exports a key or falls back to the software-key reader.
func OpenHardwareOriginalReply02(input []byte, event [16]byte, historical *Manifest, selection *ReplySelection, scope OriginalScope, custody *HardwareRecipient, current func() (OriginalAuthority, error)) (string, error) {
	if custody == nil {
		return "", ErrProtectedUnavailable
	}
	return openOriginalReply02(input, event, historical, selection, scope, current, custody.OpenCEK)
}
