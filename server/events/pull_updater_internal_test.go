// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"errors"
	"testing"

	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/events/models/testdata"
	"github.com/runatlantis/atlantis/server/events/vcs"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/metrics/metricstest"
)

type hidePrevCommentsCall struct {
	command string
	dir     string
}

type recordingHideVCSClient struct {
	*vcs.NotConfiguredVCSClient
	calls []hidePrevCommentsCall
}

func (c *recordingHideVCSClient) HidePrevCommandComments(_ logging.SimpleLogging, _ models.Repo, _ int, cmdName string, dir string) error {
	c.calls = append(c.calls, hidePrevCommentsCall{command: cmdName, dir: dir})
	return nil
}

func (c *recordingHideVCSClient) CreateComment(_ logging.SimpleLogging, _ models.Repo, _ int, _ string, _ string) error {
	return nil
}

func TestPullUpdater_HidePrevPlanComments(t *testing.T) {
	cases := []struct {
		description   string
		cmd           PullCommand
		res           command.Result
		expectedCalls []hidePrevCommentsCall
	}{
		{
			description:   "dir specified",
			cmd:           &CommentCommand{Name: command.Plan, RepoRelDir: "dirA"},
			res:           command.Result{ProjectResults: []command.ProjectResult{internalPlannedProjectResult("dirA", DefaultWorkspace, "")}},
			expectedCalls: []hidePrevCommentsCall{{command: "Plan", dir: "dirA"}},
		},
		{
			description:   "project specified uses the project's dir",
			cmd:           &CommentCommand{Name: command.Plan, ProjectName: "projA"},
			res:           command.Result{ProjectResults: []command.ProjectResult{internalPlannedProjectResult("dirA", DefaultWorkspace, "projA")}},
			expectedCalls: []hidePrevCommentsCall{{command: "Plan", dir: "dirA"}},
		},
		{
			description:   "project specified without results doesn't hide",
			cmd:           &CommentCommand{Name: command.Plan, ProjectName: "projA"},
			res:           command.Result{Error: errors.New("no project with name 'projA' is defined in atlantis.yaml")},
			expectedCalls: nil,
		},
		{
			description: "no dir or project hides all comments",
			cmd:         &CommentCommand{Name: command.Plan},
			res: command.Result{ProjectResults: []command.ProjectResult{
				internalPlannedProjectResult("dirA", DefaultWorkspace, "projA"),
				internalPlannedProjectResult("dirB", DefaultWorkspace, "projB"),
			}},
			expectedCalls: []hidePrevCommentsCall{{command: "Plan", dir: ""}},
		},
		{
			description:   "autoplan hides all comments",
			cmd:           AutoplanCommand{},
			res:           command.Result{ProjectResults: []command.ProjectResult{internalPlannedProjectResult("dirA", DefaultWorkspace, "projA")}},
			expectedCalls: []hidePrevCommentsCall{{command: "Plan", dir: ""}},
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			vcsClient := &recordingHideVCSClient{NotConfiguredVCSClient: &vcs.NotConfiguredVCSClient{Host: models.Github}}
			updater := &PullUpdater{
				HidePrevPlanComments: true,
				VCSClient:            vcsClient,
				MarkdownRenderer:     NewMarkdownRenderer(false, false, false, false, false, false, "", "atlantis", false, false),
			}

			updater.updatePull(newPullUpdaterContext(t), c.cmd, c.res)

			actualCalls := vcsClient.calls
			if len(actualCalls) != len(c.expectedCalls) {
				t.Fatalf("expected %v calls to HidePrevCommandComments, got %v", c.expectedCalls, actualCalls)
			}
			for i, expected := range c.expectedCalls {
				if actualCalls[i] != expected {
					t.Errorf("expected call %d to be %v, got %v", i, expected, actualCalls[i])
				}
			}
		})
	}
}

func TestPullUpdater_HidePrevPlanCommentsDisabled(t *testing.T) {
	vcsClient := &recordingHideVCSClient{NotConfiguredVCSClient: &vcs.NotConfiguredVCSClient{Host: models.Github}}
	updater := &PullUpdater{
		HidePrevPlanComments: false,
		VCSClient:            vcsClient,
		MarkdownRenderer:     NewMarkdownRenderer(false, false, false, false, false, false, "", "atlantis", false, false),
	}

	updater.updatePull(
		newPullUpdaterContext(t),
		&CommentCommand{Name: command.Plan, ProjectName: "projA"},
		command.Result{ProjectResults: []command.ProjectResult{internalPlannedProjectResult("dirA", DefaultWorkspace, "projA")}},
	)

	if len(vcsClient.calls) != 0 {
		t.Fatalf("expected no calls to HidePrevCommandComments, got %v", vcsClient.calls)
	}
}

func newPullUpdaterContext(t *testing.T) *command.Context {
	t.Helper()
	return &command.Context{
		User:     testdata.User,
		Log:      logging.NewNoopLogger(t),
		Scope:    metricstest.NewLoggingScope(t, logging.NewNoopLogger(t), "atlantis"),
		Pull:     testdata.Pull,
		HeadRepo: testdata.GithubRepo,
		Trigger:  command.CommentTrigger,
	}
}
