# LightAgg
Source Code of LightAgg (ICC 2027 under review). 
## Paper
LightAgg: Lightweight Sketch Aggregation for Distributed Network Measurement
## Cite
Waiting
## Abstract
Network measurement is essential for network applications (e.g., traffic engineering, congestion control, and anomaly detection). Sketch algorithms enable approximate yet resource-efficient measurement, but their distributed deployment in large-scale topologies necessitates sketch aggregation to obtain global results. However, existing aggregation schemes suffer from double counting, high latency, and lack of transmission security. To address these challenges, this paper presents LightAgg, a lightweight sketch aggregation framework. Specifically, we propose (1) an in-path duplicate elimination mechanism to prevent double counting; (2) parallel register access to reduce aggregation latency; and (3) hash-based integrity verification to ensure transmission security. Experiments on Intel Tofino switches show that LightAgg reduces double counting error by 85\%, achieves 350 ns average per‑packet processing latency, and introduces limited hardware resource overhead with proven aggregation security.
## Source Code Usage
### Overview
We have provided four .p4 files and one folders.
#### xxx.p4/
The four files respectively contain the sketch aggregation codes under four different sketches;
#### include/
It contains the supporting documents for the four P4 sketch programs.
### Setup Instructions
As for the data plane P4 program, we utilize bf-sde-9.10.0 with Intel Tofino switch.
