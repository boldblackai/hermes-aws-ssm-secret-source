# hermes-aws-ssm-secret-source

An [Hermes Agent](https://hermes-agent.nousresearch.com) **secret source**
plugin that resolves [AWS SSM Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)
secrets into environment variables at process startup — after `.env` loads,
before Hermes reads credentials. Bulk shape; on ECS it authenticates via the
**task role**, so no explicit AWS credentials need to live in `.env`.

The use case: stop enumerating every secret in CloudFormation `secrets[]`
(and redeploying for every rotation/new key). Put a parameter under the claw's
SSM prefix, restart, and spawned sessions get it as an env var.

> **Requires Hermes with [#64189](https://github.com/NousResearch/hermes-agent/pull/64189)**
> ("re-pull plugin secret sources after discovery"). On older Hermes the plugin
> registers but is **not** consulted by the first `load_hermes_dotenv()` — the
> bootstrap-timing gap ([#64177](https://github.com/NousResearch/hermes-agent/issues/64177))
> — so secrets won't reach the gateway / interactive sessions. Cron-triggered
> sessions work even without #64189 (the scheduler re-pulls). On the BoldBlack
> harness image this fix is backported until #64189 merges upstream.

## Install

```bash
hermes plugins install boldblackai/hermes-aws-ssm-secret-source --enable
```

Confirm with `/plugins` in a session. (The plugin does nothing until enabled
**and** configured, below.)

## Configure

Add to `~/.hermes/config.yaml`:

```yaml
secrets:
  sources: [aws_ssm]        # ordered; bulk sources yield to mapped ones
  aws_ssm:
    enabled: true
    path: /<claw-namespace>/   # e.g. /myclaw/ — the SSM prefix to resolve
    region: ""                 # empty = botocore default chain (AWS_REGION / profile / task role)
    recursive: true
    override_existing: true    # rotate centrally without a .env edit
```

Then restart the gateway.

Parameter → env-var mapping: `/myclaw/OPENROUTER_API_KEY` → `OPENROUTER_API_KEY`.
Sub-paths flatten: `/myclaw/db/PASSWORD` → `DB_PASSWORD`.

## Requirements

- **Hermes ≥ a build containing #64189** (see the callout above).
- **boto3** in the Hermes environment. The harness image ships it (Bedrock);
  elsewhere `pip install boto3`.
- **IAM (ECS TaskRole)** — the plugin runs in the container process, so the
  **TaskRole** (not the ExecutionRole) needs:
  ```jsonc
  { "Effect": "Allow",
    "Action": ["ssm:GetParameters", "ssm:GetParameter", "ssm:GetParametersByPath"],
    "Resource": "arn:aws:ssm:<region>:<account-id>:parameter/<claw-namespace>/*" },
  { "Effect": "Allow",
    "Action": "kms:Decrypt",
    "Resource": "<claw-ssm CMK ARN>",
    "Condition": { "StringEquals": { "kms:ViaService": "ssm.<region>.amazonaws.com" } } }
  ```

## Important caveats

- **Bootstrap provider key stays in CFN/.env.** Provider routing is configured
  at boot from the provider-key env var (cloud-mode config re-seed), which runs
  *before* plugin discovery. So the one inference-provider key the gateway
  boots on must still come from CloudFormation `secrets[]` or `.env`
  (the `Enable{OpenRouter,Anthropic,Zai}Key` dance isn't removed by this plugin).
  aws_ssm's value is **additional / rotated session-scoped keys** (no redeploy).
- **Env-var filtering still applies.** Provider-credential names on Hermes's
  `_HERMES_PROVIDER_ENV_BLOCKLIST` are stripped from subprocess (terminal /
  execute_code) envs. For a key used by a skill, name it to avoid the blocklist
  (e.g. `OPENROUTER_IMAGE_API_KEY`, not `OPENROUTER_API_KEY`) and declare it in
  the skill's `required_environment_variables`.

## See also

- Secret-source contract: <https://hermes-agent.nousresearch.com/docs/developer-guide/secret-source-plugin>
- Timing gap + fix: [NousResearch/hermes-agent#64177](https://github.com/NousResearch/hermes-agent/issues/64177) / [#64189](https://github.com/NousResearch/hermes-agent/pull/64189)
