# Repository workflow

- Use a separate Git worktree and a dedicated branch for each task that changes this repository. Create or locate that worktree before editing files, and verify the active branch with `git branch --show-current`.
- Never edit files, stage changes, or commit in the root checkout or on `main`. Use the root checkout for inspection and worktree setup.
- Keep existing changes in other worktrees intact. Run the task's build and tests from its own worktree.
