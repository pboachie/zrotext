package hpke

import "context"

// ReadHardware uses only the already qualified protected recipient. No software
// fallback or private-key export is available through this entrypoint.
func (c *OriginalCurrentClient) ReadHardware(ctx context.Context, grant string, event [16]byte, baseline uint64, custody *HardwareRecipient, clock func() uint64) (*VerifiedOriginalRead, error) {
	if custody == nil {
		return nil, OriginalHTTPError{}
	}
	return c.read(ctx, grant, event, baseline, clock, custody.OpenCEK)
}
