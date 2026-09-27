# FocusTrack Independent No-Award Evaluator Publisher

This package belongs in an independently controlled evaluator repository. It publishes a signed, public JSON feed that FocusTrack can verify automatically. It cannot award XP, rewards, or Flow.

## One-time owner setup

1. Commit this package to the evaluator repository and configure GitHub Pages to deploy from Actions. Public repositories support artifact attestations on current GitHub plans; private repositories require Enterprise Cloud. Do not change repository visibility to work around a plan restriction.
2. In the evaluator-controlled Google project, create an Ed25519 SOFTWARE Cloud KMS asymmetric signing key and a dedicated Workload Identity pool/provider. Pin the exact approved workflow commit, numeric repository and owner IDs, main branch, focustrack-evaluator environment, repository_dispatch event, and GitHub-hosted runner. Grant only cloudkms.cryptoKeyVersions.useToSign on this key. No private-key secret or service-account key is used.
3. Store the validated public signing policy as the focustrack-evaluator environment variable `FOCUSTRACK_KMS_SIGNING_POLICY`, and the key ID as `FOCUSTRACK_EVALUATOR_KEY_ID`. The separate evaluator owner must control IAM, the federation provider, repository changes, and environment variables. Pin the public key and evaluator commit in FocusTrack only after that control is verified. A key in KMS does not itself prove evaluator independence or that a result is correct.
4. Add `evaluator-policy.json` and the policy-pinned verifier module. The policy binds one source repository and one criteria hash to a verifier file hash. Its `evaluate({ baselineDirectory, candidateDirectory, binding })` function must return only `baselineResult`, `result`, `checkCount`, and `passedCount`.

## Backend dispatch

The backend calls GitHub's `repository_dispatch` endpoint with event type `focustrack_prospective_evaluation` and this exact payload:

`{ "schemaVersion": 1, "binding": { ...registeredBinding } }`

The event carries no prompts, source files, commands, paths, credentials, or claimed evaluation result. The evaluation job loads the evaluator-owned verifier and approved source commits. The verifier must enforce the baseline/candidate hashes and isolate candidate execution from its controller and result files. A new signing runner receives only evaluation JSON, recreates the original task binding, and signs via KMS. The publication job deploys the signed feed with GitHub Pages without committing to the pinned main revision. FocusTrack polls the public feed automatically. This bounded V1 feed contains the latest receipt only; persistent per-task delivery is required before a multi-user rollout.

## Safety

- The private key remains in Cloud KMS. Short-lived identity/access tokens remain in signing-process memory and are never logged or saved by the publisher.
- Only the signing job requests KMS access. Candidate code never runs in that job. This does not replace sandboxing inside the evaluation job.
- Require review for changes to evaluator code and IAM; routine evaluations need no human approval. Configuring required environment reviewers would pause every run.
- The feed contains only signed receipt envelopes.
- The publisher refuses malformed, retrospective, or award-bearing payloads.
- A successful import remains no-award. It is evidence for later Gate H review, not authority to change XP.

## Setup checks

The repository-dispatch action `focustrack_signing_selftest` runs a synthetic receipt through the real cloud signer. A manual workflow run deliberately uses the unapproved `workflow_dispatch` event and must be rejected by Google's identity condition. Both publish labeled setup artifacts, never genuine task results or awards. Neither enrolls trust in FocusTrack or establishes independent ownership. Do not treat a green setup check as a passed work evaluation.
