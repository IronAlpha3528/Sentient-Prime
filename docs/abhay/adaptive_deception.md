# Adaptive Deception

Adaptive Deception is Sentinel-Prime's mechanism for "AI-Driven Active Hypothesis Testing." It allows the platform to safely confirm suspected breaches when ML confidence is moderate but not high enough for disruptive containment.

## Score-Based Trigger
- **< 0.40 (Low)**: System monitors silently; no honeypot is deployed.
- **0.40 – 0.74 (Moderate)**: Full AI pipeline triggers the Deception Agent if there is testable uncertainty. A graph-guided decoy is deployed.
- **≥ 0.75 (High)**: Full AI pipeline skips deception and immediately triggers the Response Agent for containment.

## Deception Sequence
1. **Selection**: The AI Deception Agent selects a hypothesis to test and predicts the attacker's next action (e.g., SMB enumeration, credential dumping).
2. **Decoy Type**: Selects an appropriate honeytoken, such as fake credentials, isolated Conpot OT services, or fake SMB shares.
3. **Placement**: Determines a safe placement location based on the Cyber Entity Graph's predicted attack path.
4. **Execution**: A deterministic policy checks the request and deploys the decoy (e.g., hidden files using dot-prefix on Linux or `attrib +H` on Windows).
5. **Observation Window**: The system monitors for interaction (default 30 mins).

## Feedback Loops
- **If Touched**: Interaction generates high-confidence evidence. The system rebuilds the Common Evidence Object, updates the graph, re-runs the pipeline, and escalates to the Response Agent.
- **If Untouched**: The temporary decoy is cleaned up, deception evidence decays, but the event is not immediately marked as benign.
