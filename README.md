# demo-agent

The demo-agent software uses indy-sdk and django to drive a set of agents in collaboration, demonstrating a use case using a distributed ledger to share claims between issuers, provers, and verifiers.

## Agent Profiles
The demonstration builds out:
  - the trust anchor agent acting as:
    - the origin, sending schema to the ledger
    - the agent registrar, sending agent cryptonyms to the ledger
  - the BC registry agent acting as an issuer
  - the BC Org Book agent acting as
    - a W3C claims holder
    - an indy-sdk prover
  - the (PSPC) SRI agent, acting as a verifier of claims for which the BC Org Book agent is a prover.
 
## Agent Service Wrapper API
A django application serves as a front end for requests to agents, both from other agents and from non-agent actuators, to drive operations on agent wallets and the distributed ledger.

## Detailed Design
The document at `doc/agent-design.doc` specifies design, installation, configuration, and operation particulars of the demo-agent project.

