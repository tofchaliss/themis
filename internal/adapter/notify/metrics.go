package notify

// Recorder records notification delivery outcomes for observability.
// Wire metrics.RecordNotification from infrastructure/metrics at startup.
type Recorder func(channelType, status string)

func recordWith(recorder Recorder, channelType, status string) {
	if recorder != nil {
		recorder(channelType, status)
	}
}
