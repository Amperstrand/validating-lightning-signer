# VLS Improvement Proposals (VIPs)

[[_TOC_]]

Our philosophy of VIPs is to allow both timely discussion of rough ideas, while still becoming a permanent repository for more established ones. Depending on their state, VIPs may be quickly iterated on in a branch, discussed actively as part of a merge request to be merged, or commented upon after having been published.

The workflow for the VIP process is based upon those of the BIPs and Kubernetes proposal process.

## What is a VIP?

The main topic is information and technologies that support and expand the utility of the VLS as a security layer for lightning protocol. Most VIPs provide a concise, self-contained, technical description of one new concept, feature, or standard.

VIPs are intended to be a means for proposing new features and documenting design decisions that have gone into implementations. VIPs may be submitted by anyone, provided the content is of high quality, e.g., does not waste the community’s time.

## When to use VIPs?

VIPs are required for most non-trivial changes. Specifically:
- Anything that may be controversial
- Most new features (except the very smallest)
- Major changes to existing features
- Changes that are wide ranging or impact most of the project

> [!caution]
> When a proposal is controversial and it cannot be agreed upon whether it should be published, the conservative option will always be preferred: the proposal will be closed.

## How to start writing a VIP?

People wishing to submit a VIP should first describe their idea to the [#vls-dev](https://matrix.to/#/#vls-dev:matrix.org) matrix channel to gather feedback on viability and community interest before working on a formal description.

Please open a merge request to this repository only when substantial progress on the draft has been made, preferably when the draft is nearing completion.

## VIP Ownership

Each VIP is primarily owned by its authors and represents the author's opinion or recommendation. The authors are expected to foster discussion, address feedback and dissenting opinions.

> [!note]
> It's the author's responsbility to drive forward the status of VIP.

## File Naming Convention

Each VIP should be saved as `vip-<shortname>.md`, where `<shortname>` is a concise, hyphenated form of the proposal title. The shortname must be unique across all VIPs.

For example, a proposal titled "Channel Reserve Policy" would be saved as `vip-channel-reserve-policy.md`.

## Format

The format for a proposal should contain the below sections and structure for standardization and completeness purposes.

> [!tip]
> Given we are using Gitlab as Git Forge they support [Gitlab Flavoured Markdown](https://docs.gitlab.com/user/markdown/) whose features can be fully utilized.

Each VIP should consist of the following sections
- Headers: They contain metadata about VIP. Refer [below](#headers) for more details.
- Context: What is the existing state of the world? What is the new functionality/system being built?
- Goals: What are the goals/success criteria for the feature?
- Non Goals: What are important aspects explicitly out of scope/punted?
- Key considerations: What are the important considerations to factor in the design? Make sure to cover security/privacy/performance/cost considerations for the feature.
- Dependency: Make sure to call out any dependent dev work/vip which would be required prior to or for successful implementation of the VIP you are proposing. 
- Design: The high-level design in plain English. There should be no code or API references - this is meant to give the reader a quick overview into the proposed approach. This is not to say the design should be vague - it should be specific and well thought out. Make sure to discuss design assumptions / tradeoffs / alternatives.
- Implementation details: [Fine to fill this after the design above is finalized] Describe how the feature will be implemented. Be descriptive about API changes, different components involved and their role.
- Test plan:

Important cases to consider for testing—this should inform unit tests, [functional tests](vls-core/src/node.rs), [e2e tests](vls-protocol-signer/src/handler.rs#1811-1827), [integration/system test](https://gitlab.com/lightning-signer/vls-hsmd), [fuzz testing](fuzz/src/channel.rs), etc. as well as the manual QA plans.

> [!note]
> Prefer automated testing whenever possible.

Make sure to highlight impact to CI times when introducing new jobs and cost as well (if any).

- Changelog: After plan has received approval and we are making further changes to the feature those should be documented in this section.

> [!tip]
> We highly recommend utilizing mermaid or anyother form of flow chart/diagram creation tool to ease the mental load on readers of the proposal. Diagrams help in better understanding which transitively leads to better discussions.

Feel free to skip on the `Dependency` section if there is no dependency and the changes being proposed will be implemented in isolation.

### Headers

We use YAML Front Matter for headers which contain a brief metadata about the proposal.

**Title** - A brief informational title for the proposal.

**Authors** - The names (or pseudonyms) and email addresses of all authors of the VIP. The format of each authors header value must be

```
authors:
- Random J. User <address@dom.ain>
- Anata Sample <anata@domain.example>
```

**Last Modified** - Date of last modification to the proposal.

**Status**: The stage of the workflow it can be one of:
- Designing: Pending approval from the community and maintainers.
- Design Approved: Approved by community members and ready for implementation.
- Code Complete: Dev work has been done and changes are merged into the `main` branch.
- Stable State: Proposed changes have reached a stable state.
- Closed: Proposal was rejected or isn't going to be worked upon.

### Changelog

To help implementers understand updates to a VIP, any changes after it has reached Stable State must be tracked with version, date, and description in a Changelog section sorted by most recent version first.

Example:
```
Changelog:
- 2.0.0 (2025-01-22):
  Introduce a breaking change in the specification to fix a bug.
- 1.1.0 (2025-01-17):
  Add a backward compatible extension to the VIP.
- 1.0.1 (2025-01-15):
  Clarify an edge case and add corresponding test vectors.
- 1.0.0 (2025-01-14):
  Complete planned work on the VIP.
