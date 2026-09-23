# Jules reviews

Jules reviews an owner-authored PR when it is opened ready for review or leaves draft. The owner can also comment `/jules review` on a same-repository PR to request a fresh review, or `/jules address` to ask Jules to work through its review comments. The Actions workflow polls for the result and posts an advisory PR review from `github-actions[bot]` with a link to the Jules session. It never approves or merges a PR, and Jules does not publish comment fixes automatically.

The integration runs from the trusted `main` workflow. It does not check out PR code in Actions. The API key is stored in the repository's `JULES_API_KEY` Actions secret and is sent only to Jules over HTTPS. Workflow dispatch with a PR number and mode is also available to repository maintainers.

Reviews are limited to branches in this repository. A review is marked stale if the PR head changes while Jules is working; request a new one after updating the branch. Treat Jules findings as a second opinion alongside CI and maintainer review.
