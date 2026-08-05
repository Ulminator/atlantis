// Copyright 2025 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"slices"

	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/vcs"
)

type PullUpdater struct {
	HidePrevPlanComments bool
	VCSClient            vcs.Client
	MarkdownRenderer     *MarkdownRenderer
}

func (c *PullUpdater) updatePull(ctx *command.Context, cmd PullCommand, res command.Result) {
	// Log if we got any errors or failures.
	if res.Error != nil {
		ctx.Log.Err("%s", res.Error.Error())
	} else if res.Failure != "" {
		ctx.Log.Warn("%s", res.Failure)
	}

	// HidePrevCommandComments will hide old comments left from previous runs to reduce
	// clutter in a pull/merge request. This will not delete the comment, since the
	// comment trail may be useful in auditing or backtracing problems.
	if c.HidePrevPlanComments {
		dir, ok := hidePrevCommentsDir(cmd, res)
		if !ok {
			ctx.Log.Debug("not hiding previous plan comments for project: '%v' because its directory is unknown", cmd.Project())
		} else {
			ctx.Log.Debug("hiding previous plan comments for command: '%v', directory: '%v'", cmd.CommandName().TitleString(), dir)
			if err := c.VCSClient.HidePrevCommandComments(ctx.Log, ctx.Pull.BaseRepo, ctx.Pull.Num, cmd.CommandName().TitleString(), dir); err != nil {
				ctx.Log.Err("unable to hide old comments: %s", err)
			}
		}
	}

	if len(res.ProjectResults) > 0 {
		var commentOnProjects []command.ProjectResult
		for _, result := range res.ProjectResults {
			if slices.Contains(result.SilencePRComments, cmd.CommandName().String()) {
				ctx.Log.Debug("silenced command '%s' comment for project '%s'", cmd.CommandName().String(), result.ProjectName)
				continue
			}
			commentOnProjects = append(commentOnProjects, result)
		}

		if len(commentOnProjects) == 0 {
			return
		}

		res.ProjectResults = commentOnProjects
	}

	comment := c.MarkdownRenderer.Render(ctx, res, cmd)
	if err := c.VCSClient.CreateComment(ctx.Log, ctx.Pull.BaseRepo, ctx.Pull.Num, comment, cmd.CommandName().String()); err != nil {
		ctx.Log.Err("unable to comment: %s", err)
	}
}

// hidePrevCommentsDir returns the directory that previous comments are matched
// against when hiding them, and whether they should be hidden at all.
//
// Commands that target a project by name, ex. `atlantis plan -p project`, don't
// set a directory, so it's taken from the project that was run. Without it every
// previous comment for the command is hidden, including the comments of projects
// that this command didn't run on.
func hidePrevCommentsDir(cmd PullCommand, res command.Result) (string, bool) {
	if cmd.Dir() != "" || cmd.Project() == "" {
		return cmd.Dir(), true
	}
	if len(res.ProjectResults) == 1 && res.ProjectResults[0].RepoRelDir != "" {
		return res.ProjectResults[0].RepoRelDir, true
	}
	return "", false
}
