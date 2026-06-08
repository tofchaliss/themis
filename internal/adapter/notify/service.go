package notify

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

// ServiceConfig configures notification routing and delivery.
type ServiceConfig struct {
	Rules        domain.NotificationConfigRepository
	SMTP         SMTPSettings
	MaxRetry     int
	BaseDelay    time.Duration
	Logger       *slog.Logger
	RecordMetric Recorder
}

// Service routes domain events to configured notification channels.
type Service struct {
	rules        domain.NotificationConfigRepository
	smtp         SMTPSettings
	maxRetry     int
	baseDelay    time.Duration
	logger       *slog.Logger
	recordMetric Recorder
	digest       *digestAccumulator
	sleep        func(time.Duration)
	smtpDial     smtpDialer
	httpPost     httpPoster
	httpClient   *http.Client
}

// NewService creates a notification service.
func NewService(cfg ServiceConfig) *Service {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	maxRetry := cfg.MaxRetry
	if maxRetry <= 0 {
		maxRetry = 3
	}
	baseDelay := cfg.BaseDelay
	if baseDelay <= 0 {
		baseDelay = time.Second
	}
	return &Service{
		rules:        cfg.Rules,
		smtp:         cfg.SMTP,
		maxRetry:     maxRetry,
		baseDelay:    baseDelay,
		logger:       logger,
		recordMetric: cfg.RecordMetric,
		digest:       newDigestAccumulator(),
		sleep:        time.Sleep,
		smtpDial:     (&net.Dialer{}).DialContext,
		httpPost:     defaultHTTPPoster,
		httpClient:   http.DefaultClient,
	}
}

var _ domain.NotificationSender = (*Service)(nil)

// Dispatch evaluates routing rules and delivers matching notifications.
func (s *Service) Dispatch(ctx context.Context, event domain.NotificationEvent) error {
	if event.BatchKey != "" && len(event.Findings) <= 1 {
		s.digest.add(event)
		return nil
	}
	return s.dispatchEvent(ctx, event)
}

// FlushDigest delivers a buffered digest for the given batch key.
func (s *Service) FlushDigest(ctx context.Context, batchKey string) error {
	event, ok := s.digest.take(batchKey)
	if !ok {
		return nil
	}
	return s.dispatchEvent(ctx, event)
}

func (s *Service) dispatchEvent(ctx context.Context, event domain.NotificationEvent) error {
	if s.rules == nil {
		return nil
	}
	rules, err := s.rules.ListRules(ctx)
	if err != nil {
		return err
	}
	matched := matchingRules(rules, event)
	if len(matched) == 0 {
		return nil
	}
	var firstErr error
	for _, rule := range matched {
		if err := s.deliverRule(ctx, rule, event); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Service) deliverRule(ctx context.Context, rule domain.NotificationRule, event domain.NotificationEvent) error {
	switch rule.Channel {
	case domain.NotificationChannelEmail:
		return s.deliverEmail(ctx, rule.Destination, event)
	case domain.NotificationChannelWebhook:
		return s.deliverTeams(ctx, rule.Destination, event)
	case domain.NotificationChannelSlack:
		s.logger.Info("slack channel not implemented in phase 1", "rule", rule.Name)
		return nil
	default:
		return fmt.Errorf("unsupported notification channel %q", rule.Channel)
	}
}

func (s *Service) deliverEmail(ctx context.Context, to string, event domain.NotificationEvent) error {
	subject, body := buildEmailBody(event)
	err := withRetry(ctx, s.maxRetry, s.baseDelay, s.sleep, func(attempt int) {
		recordWith(s.recordMetric, channelTypeEmail, "retried")
		s.logDelivery("smtp retry", channelTypeEmail, attempt, to, "", nil)
	}, func() error {
		return sendSMTP(ctx, s.smtp, to, subject, body, s.smtpDial)
	})
	if err != nil {
		recordWith(s.recordMetric, channelTypeEmail, "failure")
		s.logDelivery("smtp delivery failed", channelTypeEmail, s.maxRetry, to, s.smtp.Password, err)
		return err
	}
	recordWith(s.recordMetric, channelTypeEmail, "success")
	s.logDelivery("smtp delivered", channelTypeEmail, 0, to, s.smtp.Password, nil)
	return nil
}

func (s *Service) deliverTeams(ctx context.Context, webhookURL string, event domain.NotificationEvent) error {
	payload := buildTeamsCard(event)
	err := withRetry(ctx, s.maxRetry, s.baseDelay, s.sleep, func(attempt int) {
		recordWith(s.recordMetric, channelTypeTeams, "retried")
		s.logDelivery("teams retry", channelTypeTeams, attempt, redactURL(webhookURL), "", nil)
	}, func() error {
		return postTeamsWebhook(ctx, s.httpClient, webhookURL, payload, s.httpPost)
	})
	if err != nil {
		recordWith(s.recordMetric, channelTypeTeams, "failure")
		s.logDelivery("teams delivery failed", channelTypeTeams, s.maxRetry, redactURL(webhookURL), "", err)
		return err
	}
	recordWith(s.recordMetric, channelTypeTeams, "success")
	s.logDelivery("teams delivered", channelTypeTeams, 0, redactURL(webhookURL), "", nil)
	return nil
}

func (s *Service) logDelivery(msg, channel string, attempt int, destination, secret string, err error) {
	logMsg := fmt.Sprintf("%s channel=%s destination=%s attempt=%d", msg, channel, destination, attempt)
	if secret != "" {
		logMsg += fmt.Sprintf(" password=%s", secret)
	}
	if err != nil {
		logMsg += fmt.Sprintf(" error=%v", err)
	}
	s.logger.Info(redactLogMessage(logMsg))
}
