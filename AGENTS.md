# Repository workflow

- Use a separate Git worktree and a dedicated branch for each task that changes this repository. Create or locate that worktree before editing files, and verify the active branch with `git branch --show-current`.
- Never edit files, stage changes, or commit in the root checkout or on `main`. Use the root checkout for inspection and worktree setup.
- Keep existing changes in other worktrees intact. Run the task's build and tests from its own worktree.
- Name branches after the task. Leave agent names, agent-specific prefixes, and agent versions out of branch names.
- Keep agent names and versions out of all commit messages and metadata, including titles, bodies, trailers, and author or committer identities. Check the final squash commit message for agent attribution before merging.
- Never use em dashes in new or edited text, including commit messages and pull request descriptions.
- Before every commit, format and lint the files going into it with the applicable project tools. Fix formatting and lint issues before committing.

## Shipping to `main`

- Open a draft pull request against `main` whenever you want CI feedback during development. CI runs on the draft and reruns when you push new commits to the branch.
- When the user says **ship**, push the task branch and reuse its open pull request or create one if needed. Mark a draft ready for review. If CI is pending, enable squash auto-merge. If the pull request already meets every merge requirement, squash-merge it directly through GitHub.
- Keep the pull request up to date with `main` and wait for all required checks to pass. Verify that the pull request merged as a single commit before cleaning up the local task worktree and branch. GitHub deletes the remote head branch after the merge. Preserve unrelated changes and worktrees.
