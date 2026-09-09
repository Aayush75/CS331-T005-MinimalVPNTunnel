# Prompts

These are only the main prompts that we gave during the project. We also gave many minor prompts for small changes, fixes, checks, and edits, which cannot all be mentioned here. The prompts below are shortened versions of the main requests.

## ChatGPT Web — learning and security ideation

1. "explain how a basic userspace vpn tunnel using a tun interface and udp works, including how packets move between the two systems"
2. "we have decided to make the vpn in userspace and have worked on the basic architecture and header design ourselves. help us ideate the security part of the project"
3. "what encryption, authentication, key exchange, nonce, and replay protection methods can be used for this project? we are using raspberry pi 5 devices"

## Codex — planning and implementation

1. "go through the project plan and the architecture and header design that we have decided. make a detailed implementation plan before starting the coding"
2. "implement the complete minimal vpn tunnel in c based on the finalized plan. keep the code modular and handle errors properly"
3. "implement both plaintext and encrypted modes, along with peer authentication, key exchange, authenticated encryption, sequence numbers, and replay protection"
4. "create all the supporting build, setup, cleanup, deployment, packet capture, and test scripts needed for the project. we will handle the raspberry pi environment setup and run the commands ourselves"
5. "review the entire implementation for security issues, memory safety issues, incorrect packet handling, and edge cases. fix any problems that you find"
6. "ensure the tests are comprehensive and robust, and ensure that all tests are passed. include tests for the protocol header, encryption, handshake, replay protection, invalid packets, and tampered packets"
7. "check the complete repository and make sure the code, scripts, configuration examples, and technical documentation are consistent with each other"

## Codex — report

1. "create the complete project report using the implementation, documentation, packet captures, and benchmark results that we provide. do not invent any measurements or results"
2. "include the architecture, packet flow, protocol header, security design, implementation details, testing, benchmark analysis, limitations, and future work"
3. "add clear diagrams, tables, and graphs where needed, and make sure every claim matches the code or the saved results"
4. "review the complete report for technical correctness, formatting, readability, and page layout. we will make the final changes and edits"

## ChatGPT Work — presentation

1. "create a complete presentation for the minimal vpn tunnel project based on the report and project files"
2. "create a presentation with a duration of seven minutes. cover the architecture, packet flow, security, implementation, testing, and benchmark results"
3. "use clear diagrams and charts from the actual project data, keep the slides readable"
