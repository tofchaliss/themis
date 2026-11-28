package connector

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The value rules of D31. Each kind of value is checked by its own rule; none of them lets
// shell or script syntax through, and no value is ever joined into a command: values travel to
// the build system as API parameters only.

// The rule names a schema may use.
const (
	RuleBranch       = "branch"
	RuleImageTag     = "image_tag"
	RuleRegistryPath = "registry_path"
	RuleEnum         = "enum"
	RuleBool         = "bool"
	RuleInt          = "int"
	RuleText         = "text"
)

// reservedPrefix marks the parameters the connector sets itself. A build profile may not set
// them.
const reservedPrefix = "THEMIS_"

// maxParamLen is the upper bound of every length limit.
const maxParamLen = 1024

var (
	paramName    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	jobSegment   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	reBranch     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
	reImageTag   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	reRegistry   = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	reInt        = regexp.MustCompile(`^-?[0-9]{1,18}$`)
	reText       = regexp.MustCompile(`^[A-Za-z0-9 _.,:@/+=-]*$`)
	reCVE        = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	defaultLimit = map[string]int{RuleBranch: 255, RuleImageTag: 128, RuleRegistryPath: 255, RuleEnum: 128, RuleBool: 5, RuleInt: 19, RuleText: 255}
)

// valid checks a rule of the configuration.
func (r ParamRule) valid() error {
	if _, ok := defaultLimit[r.Rule]; !ok {
		return fmt.Errorf("unknown rule %q (known: branch, image_tag, registry_path, enum, bool, int, text)", r.Rule)
	}
	if r.MaxLen < 0 || r.MaxLen > maxParamLen {
		return fmt.Errorf("max_len must be between 0 and %d", maxParamLen)
	}
	if r.Rule == RuleEnum && len(r.Values) == 0 {
		return errors.New("rule enum needs values")
	}
	return nil
}

// check tests one value against the rule.
func (r ParamRule) check(value string) error {
	limit := r.MaxLen
	if limit == 0 {
		limit = defaultLimit[r.Rule]
	}
	if len(value) > limit {
		return fmt.Errorf("longer than %d characters", limit)
	}
	ok := false
	switch r.Rule {
	case RuleBranch:
		ok = reBranch.MatchString(value) && !strings.Contains(value, "..") && !strings.Contains(value, "//") &&
			!strings.HasSuffix(value, "/") && !strings.HasSuffix(value, ".") && !strings.HasSuffix(value, ".lock")
	case RuleImageTag:
		ok = reImageTag.MatchString(value)
	case RuleRegistryPath:
		ok = reRegistry.MatchString(value)
	case RuleEnum:
		for _, v := range r.Values {
			ok = ok || v == value
		}
	case RuleBool:
		ok = value == "true" || value == "false"
	case RuleInt:
		ok = reInt.MatchString(value)
	case RuleText:
		ok = reText.MatchString(value)
	}
	if !ok {
		return fmt.Errorf("not a valid %s value", r.Rule)
	}
	return nil
}

// jobPath turns "team/build-image" into the Jenkins path "/job/team/job/build-image". Every
// segment is checked, so a job name can never carry a path or a query of its own.
func jobPath(job string) (string, error) {
	if job == "" {
		return "", errors.New("the job name is empty")
	}
	var b strings.Builder
	for _, seg := range strings.Split(job, "/") {
		if !jobSegment.MatchString(seg) || seg == "." || seg == ".." {
			return "", fmt.Errorf("job name %q is not allowed", job)
		}
		b.WriteString("/job/" + seg)
	}
	return b.String(), nil
}

// profileParams turns the `parameters` of a build profile into text values. A text, a number
// and a truth value are taken; a list or an object is refused, because the reference
// connector passes no structured value (D31 item 3).
func profileParams(raw map[string]any) (map[string]string, error) {
	out := make(map[string]string, len(raw))
	for name, v := range raw {
		switch x := v.(type) {
		case string:
			out[name] = x
		case bool:
			out[name] = strconv.FormatBool(x)
		case float64:
			out[name] = strconv.FormatFloat(x, 'f', -1, 64)
		default:
			return nil, fmt.Errorf("parameter %q is not a text, a number or true/false", name)
		}
	}
	return out, nil
}

// checkParams applies the schema of the job to the parameters (D18 items 2 and 3, D31).
func (s JobSchema) checkParams(params map[string]string) error {
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rule, ok := s.Parameters[name]
		if !ok {
			return fmt.Errorf("parameter %q is not in the schema of this job", name)
		}
		if err := rule.check(params[name]); err != nil {
			return fmt.Errorf("parameter %q: %w", name, err)
		}
	}
	required := make([]string, 0)
	for name, rule := range s.Parameters {
		if _, ok := params[name]; rule.Required && !ok {
			required = append(required, name)
		}
	}
	if len(required) > 0 {
		sort.Strings(required)
		return fmt.Errorf("required parameter %q is missing", required[0])
	}
	return nil
}
