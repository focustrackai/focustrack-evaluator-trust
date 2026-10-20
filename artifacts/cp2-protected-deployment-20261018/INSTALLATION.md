# EX538: protected GitHub deployment receiver

Status: LOCAL_IMPLEMENTATION, NOT_PUBLISHED, NOT_INSTALLED.
This packet replaces the EX537 implementation wait, not any independent custody
requirement. CP1 stays closed. No task, observation, evaluator or XP ran here.

## What is built

- `.github/workflows/deploy-protected-registration.yml`: reusable, default-off
  GitHub-hosted workflow. It checks out the actual immutable callee commit from
  GitHub's OIDC claims, never caller-selected source. Its checkout action and
  Node binary are pinned. No caller secrets, credential files, caches or artifacts.
- `scripts/protected-registration-deploy.js`: the bounded receiver. Google STS
  validates the signed GitHub token against an independently installed condition.
  The JWT audience pins one private approval document's canonical SHA256. The
  STS exchange audience is separately the fixed Google provider resource.
  It reads the exact hash/generation-bound approval, impersonates only its
  independently selected existing deployment account, validates live prestate
  and exact registration IAM, and stages the disabled existing producer and an
  untagged zero-normal-traffic dispatcher candidate. It does not run a job.
- `scripts/prepare-protected-deployment.js`: offline generator for a canonical
  private approval document, exact one-time bootstrap REST request packet, and
  thin caller pinned to the published reusable workflow commit.
- `tests/protected-registration-deploy.test.js`: synthetic provider/HTTP tests.
  These tests do not establish real cloud permissions or installation.

## Exact one-time installation boundary

Use one independently controlled installation context outside BOTH working
agents. No owner sign-in in their sessions, new service account, runtime-account
repurposing or Supabase credential is part of this implementation.

The following is the exact LOCAL PACKET GENERATION command, not a deployment:

```powershell
node scripts/prepare-protected-deployment.js --input independently-approved-install.json --out artifacts/cp2-protected-deployment-install-once
```

The input is an actual independently assembled JSON object with `plan` and
`bootstrap`, as validated in the two scripts. It is NOT a supplied ready-to-run
file: required current values are not known, and no fake live input was written.
The command fails before creating output when required inputs are missing and
refuses to overwrite an earlier packet. The synthetic fixture is TEST ONLY.

After independent exact-source review and approved publication, the installation
context supplies these real values once:

1. Published receiver commit and numeric caller repository/owner IDs; an eligible
   EXISTING deployment account and its current policy. The existing account name
   is not established here. Reject broader inherited/direct authority, keys or
   impersonation paths available to either agent. No runtime/build/signing account.
2. Complete current pool/provider inventory and custody evidence. The generator
   accepts only existing GitHub providers mapping `google.subject=assertion.sub`;
   their `repo:` subjects cannot mint this provider's `ft-install-<ID>` subject.
   Complete inventory and absence of an alternative trust path require actual
   independent provider evidence; a caller-supplied list is not that proof.
3. EX533 context built ONCE through the existing 600-second two-image recipe,
   exact resulting digests and provenance; disabled Edge staging through separate
   existing Supabase authority. Neither action is executed by this receiver.
4. Genuine native task-bound registered policy; existing registration bucket and
   exact 7/5/1 grants installed independently using EX533 INSTALLATION.md. Existing
   history three-object grant is verification-only. No protected evidence is
   created during installation; no observation clock is started by staging.
5. Fresh service/job/worker full metadata hashes, UIDs and etags; explicit current
   revision traffic, not `latest`. Job must already be disabled. Existing signing,
   source reader, trust, secrets and runtime settings must match. The receiver
   changes only images, registration policy, its self-template hash and off gates.
6. Fresh v3 IAM prestate/etags for project, controls bucket, deployment account and
   both runtime accounts. All three proposed install role names and the proposed
   `pinned-deployment` provider must be absent. Existing resources are not replaced.

Generator outputs:

- `approved-plan.json`: private canonical bytes; never publish it as a GitHub file.
- `bootstrap-requests.json`: exact method/URL/body, prior-state hashes, etags,
  no-retry rules, recovery and verification requirements for ONE installation.
  This is a reviewable request packet, NOT an automatic IAM applier.
- `stage-approved-registration.yml`: manual caller pinned to the full receiver
  commit and approved-document SHA; not a floating branch or editable script.

The independent installation applies those exact request bodies only after
fresh prestate comparison. They create three custom roles, one DISABLED provider
in the existing history pool, conditional service/job permissions, worker read
permission, metadata reads, exact journal get/create, one approved-object read,
and actAs on ONLY the two existing runtime accounts. They never give runtime
identities IAM administration, signing changes or installation control.
The deployment account's metadata-reader role reads project metadata, including
bucket IAM; it has no IAM writes, bucket/object delete, signing or job execution.
Cloud Run update/actAs permissions are powerful: immutable code plus independently
pinned inputs and trust control constrain their use. IAM alone does not validate
request bodies. The generator cannot itself prove independent control.

Keep the provider disabled and the environment variable absent/0 after setup.
Create the named `protected-registration-install` GitHub environment with current
required protections and no bypass/self-review as applicable; environment name
alone is not an authority boundary. Enablement and dispatch require their exact
stage authority and terminal setup/readback evidence, not this document alone.

## Verification and recovery

- Compare every applied IAM/provider/configuration readback, including policy
  etags and unrelated retained bindings. Unknown outcomes stop the setup; inspect
  returned provider operations. Never repeat because a resource appears absent.
- The approval hash excludes its derived provider condition/audience, preventing
  self-reference. Controls IAM fingerprints omit etag and ONLY the two exact
  verified install bindings; every other policy field remains bound.
- Receiver creates an installation intent and each step intent with generation
  precondition zero, then pins/readbacks their generations before PATCH. Journal
  names are separate from task, declaration, receipt and history records.
- Each PATCH is attempted once. The job request preserves the existing six
  mutable metadata fields from the sealed native installer. Service uses only
  `updateMask=template`; no traffic or permission mutation is available.
- Poll only the returned exact provider operation. Require terminal outcome plus
  UID/generation/config/traffic readback. Changed/unknown state cannot pass.
- A later invocation with existing intent enters read-only reconciliation. It
  binds retained records, checks provider finality/current state, and never resets
  or resumes mutations. Missing operation after an uncertain PATCH stays UNKNOWN.
- Signals abort the request path. Durable intent survives termination. No cleanup
  claims are invented and there is no public tag to remove. Restore only after
  comparing current state against this installation's exact owned poststate and
  obtaining the narrowly required recovery authority; no automatic rollback.
- Entire hosted receiver has a 600-second abort, individual HTTPS calls including
  body reads have 15 seconds, and no request retries or token-refresh resubmission.
  A timeout cannot prove a provider mutation stopped.

## What the evidence does not prove

Local tests prove neither GitHub execution nor real IAM restrictions. Build,
boundary and Edge evidence hashes are independently approved input references,
not live records verified by this receiver. Provider-generated extra defaults
may cause conservative readback rejection; do not weaken equality without new
specific evidence. No actual GitHub workflow-service validation is claimed.

The concrete next external step is publishing the reviewed receiver and having
the independent installation context bind its commit and complete the current
one-time packet. Missing values: published commit, eligible existing deployment
account/current scope, new two-image provenance, disabled Edge readback, fresh
task policy and provider prestate. These are not requests for another general
approval or a phone/login loop. No installable final packet is claimed yet.

## Primary API references

- https://docs.github.com/en/actions/reference/security/oidc
- https://docs.cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token
- https://docs.cloud.google.com/iam/docs/federated-identity-supported-services
- https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/patch
- https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.jobs/patch
- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.roles/create

Google requires service-account impersonation for this Cloud Run route; direct
federation is used only to read the exact approved Storage object. Google OIDC
does not confer Supabase deployment authority.
