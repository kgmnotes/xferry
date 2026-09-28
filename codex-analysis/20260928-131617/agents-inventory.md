# Available Agents Inventory
_Generated: 2026-09-28 13:16:17 +0300_

## Built-in Agents

### default
- **Description:** General-purpose fallback agent.
- **Use when:** No specialized role fits a required audit area.

### worker
- **Description:** Execution-focused implementation and validation agent.
- **Use when:** Later remediation work needs a bounded owner.

### explorer
- **Description:** Fast, authoritative read-heavy codebase explorer.
- **Use when:** A later agent needs a narrowly scoped source-map question.

## Typed Spawn Agent Roles Selected for This Audit

### devops-engineer
- **Description:** CI, deployment, release automation, and environment configuration review.
- **Use when:** See the focus entry in analysis-plan.md.
- **Validation:** available in the current spawn schema

### architect-reviewer
- **Description:** Coupling, system boundaries, long-term maintainability, and design coherence.
- **Use when:** See the focus entry in analysis-plan.md.
- **Validation:** available in the current spawn schema

### documentation-engineer
- **Description:** Technical documentation fidelity to code and operator workflows.
- **Use when:** See the focus entry in analysis-plan.md.
- **Validation:** available in the current spawn schema

### qa-expert
- **Description:** Risk-based test strategy and acceptance coverage.
- **Use when:** See the focus entry in analysis-plan.md.
- **Validation:** available in the current spawn schema

### security-auditor
- **Description:** Auth, secrets, input, configuration, and supply-chain security review.
- **Use when:** See the focus entry in analysis-plan.md.
- **Validation:** available in the current spawn schema

### dx-optimizer
- **Description:** Setup time, local workflows, feedback loops, and developer/user friction.
- **Use when:** See the focus entry in analysis-plan.md.
- **Validation:** available in the current spawn schema

## Other Typed Roles

The current spawn schema also exposes the broader built-in specialist catalog. It was reviewed, but roles unrelated to Python packaging, deployment, architecture, documentation, QA, security, or installation UX were intentionally not selected.

## Custom Agents

### accessibility-tester
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/accessibility-tester.toml`
- **Description:** Use when a task needs an accessibility audit of UI changes, interaction flows, or component behavior.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### ad-security-reviewer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/ad-security-reviewer.toml`
- **Description:** Use when a task needs Active Directory security review across identity boundaries, delegation, GPO exposure, or directory hardening.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### agent-installer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/agent-installer.toml`
- **Description:** Use when a task needs help selecting, copying, or organizing custom agent files from this repository into Codex agent directories.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### agent-organizer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/agent-organizer.toml`
- **Description:** Use when the parent agent needs help choosing subagents and dividing a larger task into clean delegated threads.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### ai-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/ai-engineer.toml`
- **Description:** Use when a task needs implementation or debugging of model-backed application features, agent flows, or evaluation hooks.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### angular-architect
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/angular-architect.toml`
- **Description:** Use when a task needs Angular-specific help for component architecture, dependency injection, routing, signals, or enterprise application structure.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### api-designer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/api-designer.toml`
- **Description:** Use when a task needs API contract design, evolution planning, or compatibility review before implementation starts.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### api-documenter
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/api-documenter.toml`
- **Description:** Use when a task needs consumer-facing API documentation generated from the real implementation, schema, and examples.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### architect-reviewer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/architect-reviewer.toml`
- **Description:** Use when a task needs architectural review for coupling, system boundaries, long-term maintainability, or design coherence.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### azure-infra-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/azure-infra-engineer.toml`
- **Description:** Use when a task needs Azure-specific infrastructure review or implementation across resources, networking, identity, or automation.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### backend-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/backend-developer.toml`
- **Description:** Use when a task needs scoped backend implementation or backend bug fixes after the owning path is known.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### blockchain-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/blockchain-developer.toml`
- **Description:** Use when a task needs blockchain or Web3 implementation and review across smart-contract integration, wallet flows, or transaction lifecycle handling.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### browser-debugger
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/browser-debugger.toml`
- **Description:** Use when a task needs browser-based reproduction, UI evidence gathering, or client-side debugging through a browser MCP server.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### build-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/build-engineer.toml`
- **Description:** Use when a task needs build-graph debugging, bundling fixes, compiler pipeline work, or CI build stabilization.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### business-analyst
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/business-analyst.toml`
- **Description:** Use when a task needs requirements clarified, scope normalized, or acceptance criteria extracted from messy inputs before engineering work starts.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### chaos-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/chaos-engineer.toml`
- **Description:** Use when a task needs resilience analysis for dependency failure, degraded modes, recovery behavior, or controlled fault-injection planning.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### cli-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/cli-developer.toml`
- **Description:** Use when a task needs a command-line interface feature, UX review, argument parsing change, or shell-facing workflow improvement.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### cloud-architect
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/cloud-architect.toml`
- **Description:** Use when a task needs cloud architecture review across compute, storage, networking, reliability, or multi-service design.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### code-mapper
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/code-mapper.toml`
- **Description:** Use when the parent agent needs a high-confidence map of code paths, ownership boundaries, and execution flow before changes are made.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### code-reviewer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/code-reviewer.toml`
- **Description:** Use when a task needs a broader code-health review covering maintainability, design clarity, and risky implementation choices in addition to correctness.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### competitive-analyst
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/competitive-analyst.toml`
- **Description:** Use when a task needs a grounded comparison of tools, products, libraries, or implementation options.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### compliance-auditor
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/compliance-auditor.toml`
- **Description:** Use when a task needs compliance-oriented review of controls, auditability, policy alignment, or evidence gaps in a regulated workflow.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### content-marketer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/content-marketer.toml`
- **Description:** Use when a task needs product-adjacent content strategy or messaging that still has to stay grounded in real technical capabilities.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### context-manager
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/context-manager.toml`
- **Description:** Use when a task needs a compact project context summary that other subagents can rely on before deeper work begins.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### cpp-pro
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/cpp-pro.toml`
- **Description:** Use when a task needs C++ work involving performance-sensitive code, memory ownership, concurrency, or systems-level integration.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### csharp-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/csharp-developer.toml`
- **Description:** Use when a task needs C# or .NET application work involving services, APIs, async flows, or application architecture.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### customer-success-manager
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/customer-success-manager.toml`
- **Description:** Use when a task needs support-pattern synthesis, adoption risk analysis, or customer-facing operational guidance from engineering context.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### data-analyst
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/data-analyst.toml`
- **Description:** Use when a task needs data interpretation, metric breakdown, trend explanation, or decision support from existing analytics outputs.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### data-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/data-engineer.toml`
- **Description:** Use when a task needs ETL, ingestion, transformation, warehouse, or data-pipeline implementation and debugging.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### data-researcher
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/data-researcher.toml`
- **Description:** Use when a task needs source gathering and synthesis around datasets, metrics, data pipelines, or evidence-backed quantitative questions.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### data-scientist
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/data-scientist.toml`
- **Description:** Use when a task needs statistical reasoning, experiment interpretation, feature analysis, or model-oriented data exploration.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### database-administrator
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/database-administrator.toml`
- **Description:** Use when a task needs operational database administration review for availability, backups, recovery, permissions, or runtime health.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### database-optimizer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/database-optimizer.toml`
- **Description:** Use when a task needs database performance analysis for query plans, schema design, indexing, or data access patterns.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### debugger
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/debugger.toml`
- **Description:** Use when a task needs deep bug isolation across code paths, stack traces, runtime behavior, or failing tests.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### dependency-manager
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/dependency-manager.toml`
- **Description:** Use when a task needs dependency upgrades, package graph analysis, version-policy cleanup, or third-party library risk assessment.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### deployment-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/deployment-engineer.toml`
- **Description:** Use when a task needs deployment workflow changes, release strategy updates, or rollout and rollback safety analysis.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### devops-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/devops-engineer.toml`
- **Description:** Use when a task needs CI, deployment pipeline, release automation, or environment configuration work.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### devops-incident-responder
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/devops-incident-responder.toml`
- **Description:** Use when a task needs rapid operational triage across CI, deployments, infrastructure automation, and service delivery failures.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### django-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/django-developer.toml`
- **Description:** Use when a task needs Django-specific work across models, views, forms, ORM behavior, or admin and middleware flows.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### docker-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/docker-expert.toml`
- **Description:** Use when a task needs Dockerfile review, image optimization, multi-stage build fixes, or container runtime debugging.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### docs-researcher
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/docs-researcher.toml`
- **Description:** Use when a task needs documentation-backed verification of APIs, version-specific behavior, or framework options.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### documentation-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/documentation-engineer.toml`
- **Description:** Use when a task needs technical documentation that must stay faithful to current code, tooling, and operator workflows.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### dotnet-core-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/dotnet-core-expert.toml`
- **Description:** Use when a task needs modern .NET and ASP.NET Core expertise for APIs, hosting, middleware, or cross-platform application behavior.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### dotnet-framework-4.8-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/dotnet-framework-4.8-expert.toml`
- **Description:** Use when a task needs .NET Framework 4.8 expertise for legacy enterprise applications, compatibility constraints, or Windows-bound integrations.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### dx-optimizer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/dx-optimizer.toml`
- **Description:** Use when a task needs developer-experience improvements in setup time, local workflows, feedback loops, or day-to-day tooling friction.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### electron-pro
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/electron-pro.toml`
- **Description:** Use when a task needs Electron-specific implementation or debugging across main/renderer/preload boundaries, packaging, and desktop runtime behavior.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### elixir-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/elixir-expert.toml`
- **Description:** Use when a task needs Elixir and OTP expertise for processes, supervision, fault tolerance, or Phoenix application behavior.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### embedded-systems
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/embedded-systems.toml`
- **Description:** Use when a task needs embedded or hardware-adjacent work involving device constraints, firmware boundaries, timing, or low-level integration.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### erlang-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/erlang-expert.toml`
- **Description:** Use when a task needs Erlang/OTP and rebar3 expertise for BEAM processes, testing, releases, upgrades, or distributed runtime behavior.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### error-coordinator
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/error-coordinator.toml`
- **Description:** Use when multiple errors or symptoms need to be grouped, prioritized, and assigned to the right debugging or review agents.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### error-detective
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/error-detective.toml`
- **Description:** Use when a task needs log, exception, or stack-trace analysis to identify the most probable failure source quickly.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### fintech-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/fintech-engineer.toml`
- **Description:** Use when a task needs financial systems engineering across ledgers, reconciliation, transfers, settlement, or compliance-sensitive transactional flows.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### flutter-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/flutter-expert.toml`
- **Description:** Use when a task needs Flutter expertise for widget behavior, state management, rendering issues, or mobile cross-platform implementation.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### frontend-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/frontend-developer.toml`
- **Description:** Use when a task needs scoped frontend implementation or UI bug fixes with production-level behavior and quality.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### fullstack-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/fullstack-developer.toml`
- **Description:** Use when one bounded feature or bug spans frontend and backend and a single worker should own the entire path.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### game-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/game-developer.toml`
- **Description:** Use when a task needs game-specific implementation or debugging involving gameplay systems, rendering loops, asset flow, or player-state behavior.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### git-workflow-manager
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/git-workflow-manager.toml`
- **Description:** Use when a task needs help with branching strategy, merge flow, release branching, or repository collaboration conventions.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### golang-pro
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/golang-pro.toml`
- **Description:** Use when a task needs Go expertise for concurrency, service implementation, interfaces, tooling, or performance-sensitive backend paths.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### graphql-architect
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/graphql-architect.toml`
- **Description:** Use when a task needs GraphQL schema evolution, resolver architecture, federation design, or distributed graph performance/security review.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### incident-responder
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/incident-responder.toml`
- **Description:** Use when a task needs broad production incident triage, containment planning, or evidence-driven root cause analysis.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### iot-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/iot-engineer.toml`
- **Description:** Use when a task needs IoT system work involving devices, telemetry, edge communication, or cloud-device coordination.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### it-ops-orchestrator
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/it-ops-orchestrator.toml`
- **Description:** Use when a task needs coordinated operational planning across infrastructure, incident response, identity, endpoint, and admin workflows.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### java-architect
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/java-architect.toml`
- **Description:** Use when a task needs Java application or service architecture help across framework boundaries, JVM behavior, or large codebase structure.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### javascript-pro
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/javascript-pro.toml`
- **Description:** Use when a task needs JavaScript-focused work for runtime behavior, browser or Node execution, or application-level code that is not TypeScript-led.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### knowledge-synthesizer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/knowledge-synthesizer.toml`
- **Description:** Use when multiple agents have returned findings and the parent agent needs a distilled, non-redundant synthesis.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### kotlin-specialist
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/kotlin-specialist.toml`
- **Description:** Use when a task needs Kotlin expertise for JVM applications, Android code, coroutines, or modern strongly typed service logic.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### kubernetes-specialist
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/kubernetes-specialist.toml`
- **Description:** Use when a task needs Kubernetes manifest review, rollout safety analysis, or cluster workload debugging.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### laravel-specialist
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/laravel-specialist.toml`
- **Description:** Use when a task needs Laravel-specific work across routing, Eloquent, queues, validation, or application structure.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### legacy-modernizer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/legacy-modernizer.toml`
- **Description:** Use when a task needs a modernization path for older code, frameworks, or architecture without losing behavioral safety.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### legal-advisor
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/legal-advisor.toml`
- **Description:** Use when a task needs legal-risk spotting in product or engineering behavior, especially around terms, data handling, or externally visible commitments.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### llm-architect
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/llm-architect.toml`
- **Description:** Use when a task needs architecture review for prompts, tool use, retrieval, evaluation, or multi-step LLM workflows.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### m365-admin
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/m365-admin.toml`
- **Description:** Use when a task needs Microsoft 365 administration help across Exchange Online, Teams, SharePoint, identity, or tenant-level automation.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### machine-learning-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/machine-learning-engineer.toml`
- **Description:** Use when a task needs ML system implementation work across training pipelines, feature flow, model serving, or inference integration.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### market-researcher
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/market-researcher.toml`
- **Description:** Use when a task needs market landscape, positioning, or demand-side research tied to a technical product or category.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### mcp-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/mcp-developer.toml`
- **Description:** Use when a task needs work on MCP servers, MCP clients, tool wiring, or protocol-aware integrations.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### microservices-architect
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/microservices-architect.toml`
- **Description:** Use when a task needs service-boundary design, inter-service contract review, or distributed-system architecture decisions.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### ml-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/ml-engineer.toml`
- **Description:** Use when a task needs practical machine learning implementation across feature engineering, inference wiring, and model-backed application logic.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### mlops-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/mlops-engineer.toml`
- **Description:** Use when a task needs model deployment, registry, pipeline, monitoring, or environment orchestration for machine learning systems.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### mobile-app-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/mobile-app-developer.toml`
- **Description:** Use when a task needs app-level mobile product work across screens, state, API integration, and release-sensitive mobile behavior.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### mobile-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/mobile-developer.toml`
- **Description:** Use when a task needs mobile implementation or debugging across app lifecycle, API integration, and device/platform-specific UX constraints.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### multi-agent-coordinator
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/multi-agent-coordinator.toml`
- **Description:** Use when a task needs a concrete multi-agent plan with clear role separation, dependencies, and result integration.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### network-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/network-engineer.toml`
- **Description:** Use when a task needs network-path analysis, service connectivity debugging, load-balancer review, or infrastructure network design input.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### nextjs-developer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/nextjs-developer.toml`
- **Description:** Use when a task needs Next.js-specific work across routing, rendering modes, server actions, data fetching, or deployment-sensitive frontend behavior.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### nlp-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/nlp-engineer.toml`
- **Description:** Use when a task needs NLP-specific implementation or analysis involving text processing, embeddings, ranking, or language-model-adjacent pipelines.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### payment-integration
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/payment-integration.toml`
- **Description:** Use when a task needs payment-flow review or implementation for checkout, idempotency, webhooks, retries, or settlement state handling.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### penetration-tester
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/penetration-tester.toml`
- **Description:** Use when a task needs adversarial review of an application path for exploitability, abuse cases, or practical attack surface analysis.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### performance-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/performance-engineer.toml`
- **Description:** Use when a task needs performance investigation for slow requests, hot paths, rendering regressions, or scalability bottlenecks.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### performance-monitor
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/performance-monitor.toml`
- **Description:** Use when a task needs ongoing performance-signal interpretation across build, runtime, or operational metrics before deeper optimization starts.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### php-pro
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/php-pro.toml`
- **Description:** Use when a task needs PHP expertise for application logic, framework integration, runtime debugging, or server-side code evolution.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### platform-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/platform-engineer.toml`
- **Description:** Use when a task needs internal platform, golden-path, or self-service infrastructure design for developers.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### postgres-pro
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/postgres-pro.toml`
- **Description:** Use when a task needs PostgreSQL-specific expertise for schema design, performance behavior, locking, or operational database features.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### powershell-5.1-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/powershell-5.1-expert.toml`
- **Description:** Use when a task needs Windows PowerShell 5.1 expertise for legacy automation, full .NET Framework interop, or Windows administration scripts.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### powershell-7-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/powershell-7-expert.toml`
- **Description:** Use when a task needs modern PowerShell 7 expertise for cross-platform automation, scripting, or .NET-based operational tooling.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### powershell-module-architect
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/powershell-module-architect.toml`
- **Description:** Use when a task needs PowerShell module structure, command design, packaging, or profile architecture work.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### powershell-security-hardening
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/powershell-security-hardening.toml`
- **Description:** Use when a task needs PowerShell-focused hardening across script safety, admin automation, execution controls, or Windows security posture.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### powershell-ui-architect
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/powershell-ui-architect.toml`
- **Description:** Use when a task needs PowerShell-based UI work for terminals, forms, WPF, or admin-oriented interactive tooling.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### product-manager
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/product-manager.toml`
- **Description:** Use when a task needs product framing, prioritization, or feature-shaping based on engineering reality and user impact.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### project-manager
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/project-manager.toml`
- **Description:** Use when a task needs dependency mapping, milestone planning, sequencing, or delivery-risk coordination across multiple workstreams.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### prompt-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/prompt-engineer.toml`
- **Description:** Use when a task needs prompt revision, instruction design, eval-oriented prompt comparison, or prompt-output contract tightening.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### python-pro
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/python-pro.toml`
- **Description:** Use when a task needs a Python-focused subagent for runtime behavior, packaging, typing, testing, or framework-adjacent implementation.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### qa-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/qa-expert.toml`
- **Description:** Use when a task needs test strategy, acceptance coverage planning, or risk-based QA guidance for a feature or release.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### quant-analyst
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/quant-analyst.toml`
- **Description:** Use when a task needs quantitative analysis of models, strategies, simulations, or numeric decision logic.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### rails-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/rails-expert.toml`
- **Description:** Use when a task needs Ruby on Rails expertise for models, controllers, jobs, callbacks, or convention-driven application changes.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### react-specialist
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/react-specialist.toml`
- **Description:** Use when a task needs a React-focused agent for component behavior, state flow, rendering bugs, or modern React patterns.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### refactoring-specialist
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/refactoring-specialist.toml`
- **Description:** Use when a task needs a low-risk structural refactor that preserves behavior while improving readability, modularity, or maintainability.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### research-analyst
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/research-analyst.toml`
- **Description:** Use when a task needs a structured investigation of a technical topic, implementation approach, or design question.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### reviewer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/reviewer.toml`
- **Description:** Use when a task needs PR-style review focused on correctness, security, behavior regressions, and missing tests.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### risk-manager
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/risk-manager.toml`
- **Description:** Use when a task needs explicit risk analysis for product, operational, financial, or architectural decisions.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### rust-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/rust-engineer.toml`
- **Description:** Use when a task needs Rust expertise for ownership-heavy systems code, async runtime behavior, or performance-sensitive implementation.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### sales-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/sales-engineer.toml`
- **Description:** Use when a task needs technically accurate solution positioning, customer-question handling, or implementation tradeoff explanation for pre-sales contexts.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### scrum-master
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/scrum-master.toml`
- **Description:** Use when a task needs process facilitation, iteration planning, or workflow friction analysis for an engineering team.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### search-specialist
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/search-specialist.toml`
- **Description:** Use when a task needs fast, high-signal searching of the codebase or external sources before deeper analysis begins.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### security-auditor
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/security-auditor.toml`
- **Description:** Use when a task needs focused security review of code, auth flows, secrets handling, input validation, or infrastructure configuration.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### security-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/security-engineer.toml`
- **Description:** Use when a task needs infrastructure and platform security engineering across IAM, secrets, network controls, or hardening work.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### seo-specialist
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/seo-specialist.toml`
- **Description:** Use when a task needs search-focused technical review across crawlability, metadata, rendering, information architecture, or content discoverability.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### slack-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/slack-expert.toml`
- **Description:** Use when a task needs Slack platform work involving bots, interactivity, events, workflows, or Slack-specific integration behavior.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### spring-boot-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/spring-boot-engineer.toml`
- **Description:** Use when a task needs Spring Boot expertise for service behavior, configuration, data access, or enterprise API implementation.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### sql-pro
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/sql-pro.toml`
- **Description:** Use when a task needs SQL query design, query review, schema-aware debugging, or database migration analysis.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### sre-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/sre-engineer.toml`
- **Description:** Use when a task needs reliability engineering work involving SLOs, alerting, error budgets, operational safety, or service resilience.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### swift-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/swift-expert.toml`
- **Description:** Use when a task needs Swift expertise for iOS or macOS code, async flows, Apple platform APIs, or strongly typed application logic.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### task-distributor
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/task-distributor.toml`
- **Description:** Use when a broad task needs to be broken into concrete sub-tasks with clear boundaries for multiple agents or contributors.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### technical-writer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/technical-writer.toml`
- **Description:** Use when a task needs release notes, migration notes, onboarding material, or developer-facing prose derived from real code changes.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### terraform-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/terraform-engineer.toml`
- **Description:** Use when a task needs Terraform module design, plan review, state-aware change analysis, or IaC refactoring.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### terragrunt-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/terragrunt-expert.toml`
- **Description:** Use when a task needs Terragrunt-specific help for module orchestration, environment layering, dependency wiring, or DRY infrastructure structure.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### test-automator
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/test-automator.toml`
- **Description:** Use when a task needs implementation of automated tests, test harness improvements, or targeted regression coverage.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### tooling-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/tooling-engineer.toml`
- **Description:** Use when a task needs internal developer tooling, scripts, automation glue, or workflow support utilities.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### trend-analyst
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/trend-analyst.toml`
- **Description:** Use when a task needs trend synthesis across technology shifts, adoption patterns, or emerging implementation directions.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### typescript-pro
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/typescript-pro.toml`
- **Description:** Use when a task needs strong TypeScript help for types, interfaces, refactors, or compiler-driven fixes.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### ui-designer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/ui-designer.toml`
- **Description:** Use when a task needs concrete UI decisions, interaction design, and implementation-ready design guidance before or during development.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### ui-fixer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/ui-fixer.toml`
- **Description:** Use when a UI issue is already reproduced and the parent agent wants the smallest safe patch.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### ux-researcher
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/ux-researcher.toml`
- **Description:** Use when a task needs UI feedback synthesized into actionable product and implementation guidance.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### vue-expert
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/vue-expert.toml`
- **Description:** Use when a task needs Vue expertise for component behavior, Composition API patterns, routing, or state and rendering issues.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### websocket-engineer
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/websocket-engineer.toml`
- **Description:** Use when a task needs real-time transport and state work across WebSocket lifecycle, message contracts, and reconnect/failure behavior.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### windows-infra-admin
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/windows-infra-admin.toml`
- **Description:** Use when a task needs Windows infrastructure administration across Active Directory, DNS, DHCP, GPO, or Windows automation.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### wordpress-master
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/wordpress-master.toml`
- **Description:** Use when a task needs WordPress-specific implementation or debugging across themes, plugins, content architecture, or operational site behavior.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok

### workflow-orchestrator
- **Scope:** personal
- **Source:** `/home/user/.codex/agents/workflow-orchestrator.toml`
- **Description:** Use when the parent agent needs an explicit Codex subagent workflow for a complex task with multiple stages.
- **Instructions summary:** Role-specific instructions are present; the capability is summarized by the description above and private instruction text is not copied.
- **Validation:** ok
