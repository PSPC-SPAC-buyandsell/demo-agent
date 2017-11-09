# demo-agent

As part of the technology demonstrator project using Hyperledger indy to explore the use of the distributed ledger with PSPC Supplier Registration Information (SRI), the design specifies agents with service wrapper APIs to facilitate interoperability.

The current state of the project aims to fulfil a demonstration use case enabling collaboration between the SRI and the British Columbia government's The Org Book project, underpinning its Verified Organization Network (VON).

The demonstration defines four agents:
  - the Trust Anchor as:
    - schema originator
    - agent registrar on the distributed ledger
  - the BC Registrar as an issuer
  - the BC Org Book as, for BC Registrar-issued claims, both
    - a W3C claims holder
    - an indy-sdk prover
  - the PSPC-SRI as:
    - a verifier of claims that the BC Registrar issues and the Org Book proves
    - an issuer holder, and porver for its own claims of SRI registration.

The SRI agent service wrapper offers bootstrap, claim, and helper operations.

For further documentation of the protocol, design, installation, configuration, and operation of the software, refer to  `doc/agent-design.doc`.
