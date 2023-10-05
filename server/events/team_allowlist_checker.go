package events

import (
	"strings"

	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/utils"
)

// Wildcard matches all teams and all commands
const wildcard = "*"

// TeamAllowlistChecker implements checking the teams and the operations that the members
// of a particular team are allowed to perform
type TeamAllowlistChecker struct {
	rules []Rule
}

type Rule struct {
	Team    string
	Command string
	Project string
}

// NewTeamAllowlistChecker constructs a new checker
func NewTeamAllowlistChecker(logger logging.SimpleLogging, allowlist string) (*TeamAllowlistChecker, error) {
	// this needs to be updated to support projects in addition to team/command
	var rules []Rule
	pairs := strings.Split(allowlist, ",")
	if pairs[0] != "" {
		for _, pair := range pairs {
			values := strings.Split(pair, ":")
			team := strings.TrimSpace(values[0])
			command := strings.TrimSpace(values[1])
			// project is optional
			project := wildcard
			if len(values) > 2 {
				project = strings.TrimSpace(values[2])
			}
			rule := Rule{Team: team, Command: command, Project: project}
			rules = append(rules, rule)
		}
	}
	return &TeamAllowlistChecker{
		rules: rules,
	}, nil
}

func (checker *TeamAllowlistChecker) HasRules() bool {
	return len(checker.rules) > 0
}

// IsCommandAllowedForTeam returns true if the team is allowed to execute the command
// and false otherwise.
func (checker *TeamAllowlistChecker) IsCommandAllowedForTeam(team string, command string) bool {
	for _, rule := range checker.rules {

		if (rule.Team == wildcard || strings.EqualFold(rule.Team, team)) && (rule.Command == wildcard || strings.EqualFold(rule.Command, command)) {
			return true
		}
	}
	return false
}

// IsCommandAllowedForAnyTeam returns true if any of the teams is allowed to execute the command
// and false otherwise.
func (checker *TeamAllowlistChecker) IsCommandAllowedForAnyTeam(teams []string, command string) bool {
	if len(teams) == 0 {
		for _, rule := range checker.rules {
			// *:* or *:command
			// *:*:* or *:command:* or *:command:project
			if (rule.Team == wildcard) &&
				(rule.Command == wildcard ||
					strings.EqualFold(rule.Command, command)) {
				return true
			}
			// team:command:project
		}
	} else {
		for _, t := range teams {
			if checker.IsCommandAllowedForTeam(t, command) {
				return true
			}
		}
	}
	return false
}

// IsCommandAllowedForTeam returns true if the team is allowed to execute the command
// and false otherwise.
func (checker *TeamAllowlistChecker) IsCommandAllowedForTeamInProject(team string, command string, projects []string) bool {
	for _, rule := range checker.rules {

		if (rule.Team == wildcard || strings.EqualFold(rule.Team, team)) &&
			(rule.Command == wildcard || strings.EqualFold(rule.Command, command)) &&
			(rule.Project == wildcard || utils.SlicesContains(projects, rule.Project)) {
			return true
		}
	}
	return false
}

func (checker *TeamAllowlistChecker) IsCommandAllowed(teams []string, command string, projects []string) bool {
	// can len(projects) == 0???
	if len(teams) == 0 {
		for _, rule := range checker.rules {
			// user is not in a team, but we have rules like so:
			// *:*:* || *:command:* || *:*:project || *:command:project
			if (rule.Team == wildcard) &&
				(rule.Command == wildcard ||
					strings.EqualFold(rule.Command, command)) &&
				(rule.Project == wildcard ||
					utils.SlicesContains(projects, rule.Project)) {
				return true
			}
		}
	} else {
		for _, t := range teams {
			if checker.IsCommandAllowedForTeamInProject(t, command, projects) {
				return true
			}
		}
	}
	return false
}
