# Subscription Dispatcher — pre-release

Generic Python core for a proposed open-source, self-hosted agent dispatcher.
**Pre-release: not ready for production or live credentials.**

Implemented: scoped storage grants; bounded function-call execution; explicit
ChatGPT-plan transport with no API-key or alternate-provider fallback; durable
single-host queue and restart handling. Interrupted work is not automatically
retried. Storage and model tests are synthetic.

Included: initial OAuth callback and signature validation, protected credential
loading, and permanent matter/resource ownership metadata. The OAuth lifecycle
includes a loopback callback listener and explicit local consent command;
rotating refresh integration and live account verification remain unfinished.

Missing: complete OAuth lifecycle, authenticated HTTP service, private policy
compiler, deployment configuration, live account eligibility and provider tests.
The library requires trusted authentication and storage adapters. PlanSession
is not an OAuth verifier. Never construct identity or grants from model output.
No external tool credentials are given to the model.

Run offline tests with Python 3.10+ on Unix/macOS:

    python3 -m unittest discover -s tests -v

No third-party Python dependencies are required for these core tests.
Authentication tests require Node 22.12+ and the pinned MIT-licensed jose package:

    npm ci --prefix subscription_dispatcher/auth --ignore-scripts --no-audit --no-fund
    node --test tests/test_subscription*.mjs subscription_dispatcher/auth/test/*.test.mjs

Installation downloads the pinned dependency. Tests use synthetic credentials and
locally generated signing keys; they do not initiate live sign-in or inference.

OpenAI documentation:
https://developers.openai.com/siwc/token-sharing-open-source
https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms
https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference

The documented open-source/self-hosted route still requires actual account
eligibility, applicable usage terms and OAuth consent. This package is not an
OpenAI approval or a guarantee of plan entitlement. Infrastructure costs are
separate. Ordinary app-server login is not a hosted-service authorization.

Released under the MIT licence in LICENSE. This pre-release is for development
and review; it is not a production deployment or an OpenAI eligibility approval.
