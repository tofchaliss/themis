package delivery

// SetTargetForTest replaces one audience's URL after construction, to reach request-build
// failures the configure-time check would otherwise refuse.
func (d *RealWebhookDeliverer) SetTargetForTest(audience, target string) { d.cfg.Targets[audience] = target }
