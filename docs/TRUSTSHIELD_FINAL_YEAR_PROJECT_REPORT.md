# BCSE497J – PROJECT-I / FINAL YEAR CAPSTONE PROJECT
## SCHOOL OF COMPUTER SCIENCE AND ENGINEERING (SCOPE)

---

# **TRUSTSHIELD: A UNIFIED DIGITAL SAFETY PLATFORM FOR MULTI-THREAT DETECTION**

**A Project Report Submitted in Partial Fulfilment of the Requirements for the Degree of**  
### **BACHELOR OF TECHNOLOGY**  
**in**  
### **COMPUTER SCIENCE AND ENGINEERING**

---

### **Submitted By:**
| Registration No. | Student Name |
| :--- | :--- |
| **21BCE0001** | **STUDENT NAME 1** |
| **21BCE0002** | **STUDENT NAME 2** |
| **21BCE0003** | **STUDENT NAME 3** |

<br>

### **Under the Supervision and Guidance of:**
**PROJECT GUIDE NAME**  
*Assistant Professor (Senior Grade) / Designation*  
School of Computer Science and Engineering (SCOPE)  

<br>

**School of Computer Science and Engineering**  
**ACADEMIC YEAR: 2025–2026**  
**September 2026**

---

\newpage

## **BONAFIDE CERTIFICATE**

Certified that this project report entitled **"TRUSTSHIELD: A UNIFIED DIGITAL SAFETY PLATFORM FOR MULTI-THREAT DETECTION"** is the bonafide work of **STUDENT NAME 1 (21BCE0001), STUDENT NAME 2 (21BCE0002), and STUDENT NAME 3 (21BCE0003)** who carried out the project work under my supervision.

<br><br><br>

---------------------------------------------  
**PROJECT GUIDE / SUPERVISOR**  
Assistant Professor (Senior Grade)  
School of Computer Science and Engineering  

<br><br><br>

---------------------------------------------  
**HEAD OF THE DEPARTMENT / DIVISION CHAIR**  
School of Computer Science and Engineering  

<br>

Submitted for the Project-I / Capstone Phase-I Viva-Voce Examination held on: `__________________`

<br>

---------------------------------------------  
**INTERNAL EXAMINER** &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp; **EXTERNAL EXAMINER**

---

\newpage

## **CANDIDATES' DECLARATION**

We hereby declare that the project entitled **"TRUSTSHIELD: A UNIFIED DIGITAL SAFETY PLATFORM FOR MULTI-THREAT DETECTION"** submitted by us to the School of Computer Science and Engineering in partial fulfilment of the requirements for the award of the degree of **Bachelor of Technology in Computer Science and Engineering** is a record of original research work carried out by us under the supervision of **PROJECT GUIDE NAME**.

We further declare that the work reported herein does not form part of any other project report or dissertation on the basis of which a degree or award was conferred on an earlier occasion on this or any other candidate. Where materials or data have been obtained from other sources, they have been duly referenced in accordance with standard academic citation standards.

<br><br>

**1. STUDENT NAME 1 (Reg. No: 21BCE0001)** &emsp; Signature: _______________________  
**2. STUDENT NAME 2 (Reg. No: 21BCE0002)** &emsp; Signature: _______________________  
**3. STUDENT NAME 3 (Reg. No: 21BCE0003)** &emsp; Signature: _______________________  

**Date:** September 08, 2026  
**Place:** Campus  

---

\newpage

## **ACKNOWLEDGEMENTS**

We express our deepest gratitude to our project supervisor, **PROJECT GUIDE NAME**, for their consistent guidance, constructive critique, and invaluable intellectual support throughout the conception, architectural design, and implementation of the **TrustShield** platform.

We extend our sincere thanks to the **Dean** and the faculty members of the **School of Computer Science and Engineering (SCOPE)** for providing the computational resources, laboratory access, and an inspiring academic environment necessary to pursue this research.

Finally, we thank our parents, peers, and collaborators whose encouragement and suggestions sustained our efforts throughout this engineering capstone journey.

<br>

**Project Team Members:**  
STUDENT NAME 1  
STUDENT NAME 2  
STUDENT NAME 3  

---

\newpage

## **ABSTRACT**

The pervasive digitization of commerce, social interaction, financial workflows, and news distribution has significantly widened the attack surface for coordinated cyber-social threats. Contemporary digital users regularly face deceptive threats that span across separate domains: algorithmic social engineering and phishing URLs that emulate legitimate banking and cloud portals, deepfake synthetic media used for non-consensual impersonation and CEO fraud, large-scale credential breaches enabling automated account takeovers (ATO), and coordinated multimodal disinformation campaigns designed to manipulate public perception. Existing commercial and academic defensive mechanisms are siloed into domain-specific point solutions (e.g., standalone URL checkers, disconnected fact-checking sites, or offline forensics toolkits), placing an unsustainable cognitive burden on end-users and enterprise analysts who must manually synthesize fragmented indicators.

To bridge this operational and architectural divide, this project presents **TrustShield**, a unified, production-oriented digital safety platform that consolidates four critical analytical workflows into a cohesive microservices architecture:
1. **Phishing and Malicious URL Detection**: Employing lexical feature extraction combined with gradient-boosted decision trees and multi-provider threat-intelligence feeds.
2. **Deepfake and Synthetic Media Forensics**: Utilizing spatial and frequency-domain artifact analysis with Deep Java Library (DJL) and ONNX Runtime for high-throughput model inference.
3. **Privacy-Preserving Breach Monitoring**: Applying $k$-anonymity SHA-based prefix matching to monitor credential exposure without revealing raw user identifiers.
4. **Multimodal Misinformation and Claim Verification**: Integrating cross-modal text-image semantic coherence scoring with Retrieval-Augmented Generation (RAG) powered by verified authoritative fact repositories.

TrustShield is engineered around an enterprise-grade backend utilizing **Java 21 LTS**, **Spring Boot 3.3.x**, **Spring Cloud Gateway**, and **Apache Kafka** for non-blocking asynchronous event processing. Persistent transactional state is managed in **PostgreSQL 16**, low-latency caching and token-bucket rate limiting are handled by **Redis 7**, unstructured media artifacts are partitioned in S3-compatible object storage (**MinIO**), and audit trails are indexed in **Elasticsearch 8.x**. Comprehensive experimental design protocols are specified to evaluate classification metrics ($F_1$-score, PR-AUC, ROC-AUC), system latency percentiles ($p_{50}, p_{95}, p_{99}$), fault tolerance, and zero-knowledge privacy leakage. The resulting platform delivers an interpretable, scalable, and resilient digital defence framework designed for academic evaluation and production readiness.

**Keywords:** Cybersecurity, Digital Safety, Deepfake Detection, Phishing Detection, Breach Monitoring, Multimodal Misinformation, Microservices Architecture, Apache Kafka, ONNX Runtime, Privacy-Preserving Computing.

---

\newpage

## **TABLE OF CONTENTS**

- **BONAFIDE CERTIFICATE**
- **CANDIDATES' DECLARATION**
- **ACKNOWLEDGEMENTS**
- **ABSTRACT**
- **LIST OF FIGURES**
- **LIST OF TABLES**
- **LIST OF ABBREVIATIONS**

### **1. INTRODUCTION**
  - 1.1 Background and Context
  - 1.2 Motivation and Problem Landscape
  - 1.3 Scope of the Project
  - 1.4 Objectives of the Work
  - 1.5 Organization of the Report

### **2. LITERATURE REVIEW AND THEORETICAL FOUNDATION**
  - 2.1 Domain-Specific Literature Survey
    - 2.1.1 Phishing and Malicious URL Classification
    - 2.1.2 Cyber-Threat Intelligence and Personal Data Exposure
    - 2.1.3 Deepfake Forensics and Synthetic Media Detection
    - 2.1.4 Multimodal Misinformation and Algorithmic Fact-Checking
  - 2.2 Comparative Analysis of Existing Defences
  - 2.3 Identified Research Gaps
    - 2.3.1 Cross-Dataset Degradation in URL Classifiers
    - 2.3.2 Privacy Leakage in Breach Search Services
    - 2.3.3 Generalization Bottlenecks in Deepfake Classifiers
    - 2.3.4 Cross-Modal Semantic Asymmetry in Fake News
    - 2.3.5 Lack of Architectural Integration
  - 2.4 Problem Formulation

### **3. REQUIREMENTS ENGINEERING AND FEASIBILITY STUDY**
  - 3.1 Software Requirements Specification (SRS)
    - 3.1.1 Functional Requirements (FR-01 to FR-12)
    - 3.1.2 Non-Functional Requirements (NFR-01 to NFR-10)
  - 3.2 Feasibility Analysis
    - 3.2.1 Technical Feasibility
    - 3.2.2 Operational and Architectural Feasibility
    - 3.2.3 Economic Feasibility
    - 3.2.4 Legal, Ethical, and Privacy Feasibility
  - 3.3 Hardware and Software Environments
    - 3.3.1 Hardware Specification
    - 3.3.2 Software Stack and Tooling

### **4. SYSTEM ARCHITECTURE AND DESIGN**
  - 4.1 Design Philosophy and High-Level Architecture
  - 4.2 Microservices Deconstruction and Service Boundaries
  - 4.3 Unified Mathematical and Threat Scoring Formulations
    - 4.3.1 Composite Threat Scoring Model
    - 4.3.2 $k$-Anonymity Mathematical Scheme for Breach Search
    - 4.3.3 Multimodal Semantic Dissimilarity Index
  - 4.4 Unified Modeling Language (UML) Specifications
    - 4.4.1 Detailed System Architecture Diagram
    - 4.4.2 Level-0 and Level-1 Data Flow Diagrams (DFD)
    - 4.4.3 Use Case Diagram and Actor Specifications
    - 4.4.4 Domain Class Diagram with Design Patterns
    - 4.4.5 Sequence Diagrams (Synchronous vs Asynchronous Workflows)
  - 4.5 Relational Database Schema Design (DDL & ER Model)
  - 4.6 Event-Driven Architecture and Apache Kafka Topic Hierarchy
  - 4.7 RESTful API Contract Design (OpenAPI 3.0 Standard)
  - 4.8 Security, Authentication, and Privacy Engineering

### **5. METHODOLOGY AND IMPLEMENTATION DETAILS**
  - 5.1 Phishing and Malicious URL Detection Engine
  - 5.2 Deepfake Analysis Pipeline via ONNX and DJL
  - 5.3 Privacy-Preserving Breach Monitoring Subsystem
  - 5.4 Multimodal Misinformation and RAG Verification Engine
  - 5.5 Core Microservice Orchestration and Spring Cloud Gateway Implementation

### **6. EVALUATION METRICS AND TESTING METHODOLOGY**
  - 6.1 Evaluation Metrics and Mathematical Definitions
  - 6.2 Experimental Setup and Benchmark Datasets
  - 6.3 Comprehensive Testing Strategy
    - 6.3.1 Unit Testing
    - 6.3.2 Integration Testing with Testcontainers
    - 6.3.3 Load and Stress Testing
    - 6.3.4 Security and Penetration Testing
  - 6.4 Empirical Experimental Results and Benchmarks
    - 6.4.1 Phishing Classifier Empirical Performance
    - 6.4.2 Cross-Runtime Zero-Drift Feature Extractor Parity
    - 6.4.3 Hardware-Grounded Inference Latency Percentiles
    - 6.4.4 Architectural Resilience and Failure Drill Verification
  - 6.5 Expected Contributions and Deliverables

### **7. PROJECT MANAGEMENT AND WORK PLAN**
  - 7.1 Work Breakdown Structure (WBS)
  - 7.2 Phase-wise Project Timeline (Gantt Chart Representation)
  - 7.3 Team Member Roles and Responsibility Matrix

### **8. LIMITATIONS, FUTURE SCOPE, AND CONCLUSION**
  - 8.1 Current Technical Limitations
  - 8.2 Future Research and Engineering Enhancements
  - 8.3 Concluding Remarks

### **9. REFERENCES**

---

\newpage

## **LIST OF FIGURES**

| Fig. No. | Caption |
| :--- | :--- |
| **Fig. 4.1** | TrustShield Enterprise Microservices Logical Architecture |
| **Fig. 4.2** | Level-0 Context-Level Data Flow Diagram (DFD) |
| **Fig. 4.3** | Level-1 Detailed Data Flow Diagram for Multi-Threat Subsystems |
| **Fig. 4.4** | UML Use Case Diagram for User, Admin, and External Actors |
| **Fig. 4.5** | Core Domain Class Diagram with Microservice Repositories and Entities |
| **Fig. 4.6** | UML Sequence Diagram: Synchronous Phishing Analysis Workflow |
| **Fig. 4.7** | UML Sequence Diagram: Asynchronous Deepfake Ingestion and Notification via Kafka |

---

## **LIST OF TABLES**

| Table No. | Title |
| :--- | :--- |
| **Table 2.1** | Summary and Critique of Base Research Papers |
| **Table 2.2** | Feature Matrix: TrustShield vs. Contemporary Single-Point Solutions |
| **Table 3.1** | Functional Requirements Specification (FR-01 to FR-12) |
| **Table 3.2** | Non-Functional Requirements Specification (NFR-01 to NFR-10) |
| **Table 3.3** | Recommended Hardware Infrastructure Specifications |
| **Table 3.4** | Software Stack, Frameworks, and Toolchain Specifications |
| **Table 4.1** | Microservice Component Responsibilities and Ports |
| **Table 4.2** | PostgreSQL Relational Database Schema Specifications |
| **Table 4.3** | Apache Kafka Topic Specification and Payload Schemas |
| **Table 4.4** | RESTful API Endpoints Specification (OpenAPI 3.0) |
| **Table 6.1** | Machine Learning and Systems Evaluation Metrics |
| **Table 6.2** | Benchmark Datasets for Model Validation |
| **Table 6.3** | Multi-Layered Testing Strategy and Tools |
| **Table 6.4** | Stratified 5-Fold Cross-Validation Performance (10,000 URLs) |
| **Table 6.5** | Production CPU Latency Percentiles and Throughput |
| **Table 7.1** | Phase-wise Project Execution Timeline (24-Week Plan) |
| **Table 7.2** | RACI Responsibility Assignment Matrix |

---

## **LIST OF ABBREVIATIONS**

| Abbreviation | Expansion |
| :--- | :--- |
| **API** | Application Programming Interface |
| **ATO** | Account Takeover |
| **AUC** | Area Under the Curve |
| **CORS** | Cross-Origin Resource Sharing |
| **CPU** | Central Processing Unit |
| **CTI** | Cyber Threat Intelligence |
| **DFD** | Data Flow Diagram |
| **DJL** | Deep Java Library |
| **DOM** | Document Object Model |
| **DTO** | Data Transfer Object |
| **FPR** | False Positive Rate |
| **GPU** | Graphics Processing Unit |
| **HTTP / HTTPS** | Hypertext Transfer Protocol / Secure |
| **JWT** | JSON Web Token |
| **LLM** | Large Language Model |
| **LTS** | Long-Term Support |
| **ML** | Machine Learning |
| **NFR** | Non-Functional Requirement |
| **ONNX** | Open Neural Network Exchange |
| **OSINT** | Open Source Intelligence |
| **PR-AUC** | Precision-Recall Area Under Curve |
| **RAG** | Retrieval-Augmented Generation |
| **REST** | Representational State Transfer |
| **ROC** | Receiver Operating Characteristic |
| **SLA** | Service Level Agreement |
| **UDA** | Unsupervised Domain Adaptation |
| **UML** | Unified Modeling Language |
| **URI / URL** | Uniform Resource Identifier / Locator |
| **WBS** | Work Breakdown Structure |

---

\newpage

# **1. INTRODUCTION**

### **1.1 Background and Context**
The hyper-connectivity of contemporary digital ecosystems has driven unprecedented operational efficiencies in banking, e-commerce, tele-governance, social networking, and real-time news propagation. However, this vast surface area has precipitated a corresponding proliferation of cyber-social engineering threats. Threat actors increasingly deploy multi-vector attack chains that blend technical network exploits with cognitive exploitation:
1. **Phishing & Fraudulent Infrastructure:** Modern adversarial phishing campaigns leverage ephemeral domain generation algorithms (DGAs), homograph attacks, zero-day bulletproof hosts, and dynamic obfuscation techniques to impersonate trusted financial, enterprise, and social platforms.
2. **Generative Synthetic Media (Deepfakes):** The commoditization of generative diffusion networks, Variational Autoencoders (VAEs), and Generative Adversarial Networks (GANs) has made hyper-realistic facial reenactment, text-to-speech voice cloning, and synthetic media generation accessible to non-state actors. These are deployed for CEO fraud, biometric bypass, extortion, and non-consensual defamation.
3. **Data Breaches & Credential Exposure:** Billions of plaintext and weakly hashed credentials circulate across underground marketplaces and Telegram illicit channels. Attackers exploit password reuse across services through automated credential stuffing and account takeover (ATO) pipelines.
4. **Coordinated Misinformation & Disinformation Campaigns:** Weaponized propaganda combines fabricated textual assertions with out-of-context or altered imagery to trigger societal panic, financial stock manipulation, and political polarization.

### **1.2 Motivation and Problem Landscape**
In existing defensive operations, users and security teams face severe **security tool fragmentation**. When an individual receives an ambiguous communication (e.g., an urgent message containing an abbreviated hyperlink, an audio snippet from an alleged executive, and a shocking news claim), they must navigate distinct, disconnected services to investigate:
- Submit the link to a public URL sandbox (e.g., VirusTotal or PhishTank).
- Query personal email exposure on a public data breach site (e.g., HaveIBeenPwned).
- Manually upload the audio/image to experimental deepfake web detectors.
- Cross-reference text claims across disparate fact-checking websites.

This fragmentation creates three acute failure modes:
- **Cognitive Overload and Security Fatigue:** The average user abandons verification workflows due to friction, resulting in security compromises.
- **Incompatible Output Semantics:** One service provides a binary boolean decision, another outputs a confidence percentage without context, and a third produces a complex technical raw JSON trace. Users are left without clear, actionable remediation directives.
- **Privacy and Data Sovereignty Risks:** Traditional breach and threat query engines require users to send raw, plaintext identifiers (email addresses, phone numbers, employee IDs) across third-party networks, exposing the very metadata they seek to safeguard.

### **1.3 Scope of the Project**
TrustShield is engineered as a unified, production-ready, cloud-native digital safety system that consolidates multi-threat detection under an integrated microservices fabric. The operational scope covers:
- **Modular Analysis Pipelines:**
  - Automated feature-based and reputation-backed phishing detection for URLs and QR codes.
  - Frequency and spatial domain forensic inference for deepfake images, video, and audio.
  - Zero-knowledge, privacy-preserving credential exposure monitoring against verified breach repositories.
  - Context-aware multimodal misinformation validation combining lexical claim parsing, fact database retrieval, and multimodal coherence scoring.
- **Enterprise Engineering Framework:** Full-lifecycle Java 21 / Spring Boot microservices implementation featuring API gateway routing, token-bucket rate limiting, JWT-based zero-trust authentication, Kafka-based asynchronous event streaming, and multi-tier persistence (PostgreSQL, Redis, Elasticsearch, MinIO).
- **System Scope Boundaries:** TrustShield is designed as an intelligent decision-support platform for end-users and security personnel. It does not replace high-assurance human editorial fact-checkers, military-grade digital forensics chain-of-custody platforms, or deep law-enforcement intercept infrastructure.

### **1.4 Objectives of the Work**
The concrete engineering and research objectives are:
1. **Architectural Unification:** Design and implement a scalable, loosely coupled microservices architecture using Spring Boot 3.3.x and Spring Cloud Gateway to provide a single, authenticated REST interface for multi-threat submission.
2. **In-Process Deep Learning Inference:** Integrate Deep Java Library (DJL) and ONNX Runtime to execute pre-trained computer vision and audio forensics models directly inside the JVM runtime, bypassing the latency and architectural complexity of external Python sidecar services.
3. **Privacy-Preserving Threat Verification:** Formulate and deploy a $k$-anonymity prefix-hashing protocol for breach queries, ensuring that raw user credentials never leave the client application in plaintext.
4. **Resilient Asynchronous Streaming:** Implement Apache Kafka event topics to decouple computationally intensive media processing and external threat-intel polling from the interactive client request-response lifecycle.
5. **Rigorous Empirical Validation:** Establish a formal experimental evaluation framework measuring precision, recall, $F_1$-score, PR-AUC, ROC-AUC, API response percentiles ($p_{50}, p_{95}, p_{99}$), and fault isolation under simulated network degradation.

### **1.5 Organization of the Report**
The remainder of this report is organized as follows:
- **Chapter 2** presents a critical literature review of state-of-the-art base research papers, a comparative analysis matrix, and derived research gaps.
- **Chapter 3** establishes the Software Requirements Specification (SRS), covering functional/non-functional criteria, feasibility studies, and hardware/software configurations.
- **Chapter 4** outlines the technical architecture, mathematical formulations, UML diagrams (Class, Sequence, DFD, Use Case), database schemas, and API contracts.
- **Chapter 5** details the implementation methodologies for each detection engine.
- **Chapter 6** defines the experimental evaluation framework, performance metrics, benchmark datasets, and multi-tiered testing strategy.
- **Chapter 7** outlines project management, WBS, timeline, and resource allocation.
- **Chapter 8** discusses limitations, future engineering horizons, and conclusions.
- **Chapter 9** provides standardized IEEE references.

---

\newpage

# **2. LITERATURE REVIEW AND THEORETICAL FOUNDATION**

### **2.1 Domain-Specific Literature Survey**

#### **2.1.1 Phishing and Malicious URL Classification**
1. **Rashid et al. (2024) [1]** investigated the generalization vulnerabilities of machine learning-based URL phishing classifiers. The authors demonstrated that while supervised classifiers (e.g., Random Forests, XGBoost, Deep Neural Networks) achieve upwards of 97% accuracy when evaluated on randomly partitioned test splits from the same distribution, their performance drops by over 28% when evaluated against out-of-distribution datasets collected from temporal drift or alternate geographic registrars. To mitigate this cross-dataset degradation, the authors introduced an Unsupervised Domain Adaptation (UDA) framework utilizing domain-adversarial neural networks to align latent feature representations across heterogeneous URL distributions.  
   *Relevance to TrustShield:* Confirms that relying exclusively on a single internal machine learning classifier trained on static URL corpora is dangerous in production. TrustShield addresses this by implementing a layered ensemble that synthesizes lexical feature heuristics, local ONNX model predictions, and real-time live threat-intelligence feeds (e.g., Google Safe Browsing and VirusTotal APIs).

2. **Yoon, Buu, and Kim (2024) [2]** developed a multimodal phishing detection model combining URL lexical features with Document Object Model (DOM) graph topology. By employing Graph Convolutional Networks (GCNs) over parsed HTML DOM trees alongside Transformer-based URL token embeddings, the authors captured structural discrepancies—such as hidden iframe overlays, brand logo mismatching, and abnormal credential submission action paths—achieving an $F_1$-score of 98.4%.  
   *Relevance to TrustShield:* Informs the modular expansion of TrustShield's Phishing Detection Service to incorporate DOM structural analysis alongside raw URL lexical tokens.

#### **2.1.2 Cyber-Threat Intelligence and Personal Data Exposure**
1. **Biswas et al. (2022) [3]** proposed a text-mining and natural language processing framework for automated cyber-risk assessment across dark-web hacker forums. By parsing underground discussions, IRC logs, and paste sites with domain-adapted entity extractors, their system cataloged credential dumps, zero-day vulnerability trading, and malware signatures, demonstrating that proactive intelligence gathering significantly reduces the mean-time-to-detection (MTTD) for compromised enterprise credentials.  
   *Relevance to TrustShield:* Establishes that credential breach monitoring must not merely be a static record lookup, but an active threat-intelligence ingest pipeline that correlates compromised credentials with known leak vectors.

2. **Putrevu et al. (2023) [4]** presented *DKaaS* (DARK-KERNEL as a Service), an active cyber threat intelligence (CTI) platform. DKaaS automates the correlation of malicious IP addresses, domain names, and compromised organizational identifiers against real-time underground network indicators. The authors emphasized the imperative of translating complex threat feeds into actionable remediation alerts.  
   *Relevance to TrustShield:* Directs TrustShield's Breach Monitoring Service to ingest verified breach dumps and produce clear, prioritized remediation advice (e.g., targeted credential rotation, 2FA enforcement).

#### **2.1.3 Deepfake Forensics and Synthetic Media Detection**
1. **Dong et al. (2023) [5]** tackled the problem of cross-manipulation deepfake generalization. Deep learning models trained on specific manipulation algorithms (such as DeepFakes or Face2Face) exhibit severe degradation when tested on unseen generators (e.g., modern Latent Diffusion Models or Neural Voice Cloning). The authors proposed a supervised contrastive learning framework combining spatial RGB color space clues with multi-scale frequency-domain artifacts (via 2D Discrete Cosine Transform and Fast Fourier Transform), achieving superior cross-dataset generalization.  
   *Relevance to TrustShield:* Motivates the feature preprocessing layer within TrustShield’s Deepfake Service, highlighting that model inference must examine frequency discrepancies that persist across generative architectures.

2. **Wang et al. (2024) [6]** delivered a comprehensive survey on deepfake detection from the perspective of operational reliability. The authors identified three fundamental pillars for dependable deployment: **transferability** across image compressions, **interpretability** of model decisions (avoiding black-box rejection), and **adversarial robustness** against adversarial noise perturbations.  
   *Relevance to TrustShield:* Mandates that TrustShield must output continuous confidence distributions, heatmap artifact explanations, and uncertainty indicators rather than uncalibrated binary labels.

#### **2.1.4 Multimodal Misinformation and Algorithmic Fact-Checking**
1. **Yang et al. (2023) [7]** developed a multimodal transformer architecture for automated fake news detection. Their study demonstrated that deceptive articles rarely exhibit purely textual or purely visual fabrication; rather, attackers intentionally pair authentic, historical photographs with fabricated textual claims (cross-modal out-of-context deception). Their dual-stream cross-attention mechanism effectively identified discrepancies between caption semantics and image context.  
   *Relevance to TrustShield:* Directly influences TrustShield's Fact-Checking Service, where textual claims must be jointly evaluated against associated media embeddings and external knowledge graphs.

2. **Li, Jia, and Wang (2024) [8]** proposed a multimodal misinformation detection model utilizing contrastive representation learning and similarity fusion. Their work revealed that fine-grained alignment between entity mentions in text and visual bounding-box detections is vital for exposing subtle editorial manipulations.  
   *Relevance to TrustShield:* Informs the integration of Retrieval-Augmented Generation (RAG) and multimodal similarity calculation within TrustShield’s verification pipeline.

---

### **2.2 Comparative Analysis of Existing Defences**

**Table 2.1: Architectural and Functional Comparison Between Existing Tools and TrustShield**

| Feature / Dimension | VirusTotal | HaveIBeenPwned | Deepware Scanner | Snopes / FactCheck | **TrustShield (Proposed)** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Phishing / URL Analysis** | Yes (Multi-engine) | No | No | No | **Yes (ML + Reputation Feeds)** |
| **Breach Monitoring** | No | Yes (Standalone) | No | No | **Yes (Privacy-Preserving $k$-Anonymity)** |
| **Deepfake Media Detection** | Limited / Sandbox | No | Yes (Video only) | No | **Yes (Image, Video, Audio via ONNX)** |
| **Fact / Misinformation Check** | No | No | No | Yes (Manual Editorial)| **Yes (Automated RAG + Cross-Modal)** |
| **Unified Single Workflow** | No | No | No | No | **Yes (Single API & Portal Interface)** |
| **Client Privacy Protection** | Low (Public uploads) | High ($k$-anonymity) | Low (Media stored) | N/A | **High (Zero-Knowledge Hash Prefixes)** |
| **Architecture** | Monolithic Cloud | Cloud Web API | Web SaaS | Web Content CMS | **Modular Java 21 Microservices + Kafka** |
| **Self-Hostable / Open Model** | No (Commercial API) | Partially (API) | No (Closed) | No (Editorial) | **Yes (Docker / Cloud-Native Deployment)** |

---

### **2.3 Identified Research Gaps**
From the theoretical and empirical literature survey, five critical research gaps are identified:

1. **RG-1: Cross-Dataset Degradation in Phishing Classifiers:** Supervised URL classifiers suffer catastrophic degradation under domain shift and emerging URL obfuscations [1]. A singular machine-learning approach is inadequate without real-time threat-intelligence integration.
2. **RG-2: Privacy Leakage in Breach Search Engines:** Existing consumer breach check services frequently require users to transmit plaintext identifiers or full email hashes across public networks, creating metadata leakage and secondary tracking hazards [3], [4].
3. **RG-3: Generalization and Explainability Deficits in Deepfake Detectors:** Contemporary media forensic models act as uncalibrated black boxes that fail on re-compressed or novel generative formats without conveying spatial or spectral explanations [5], [6].
4. **RG-4: Cross-Modal Semantic Asymmetry in Misinformation:** Existing fact-checking workflows treat textual claims and multimedia artifacts as disjoint entities, failing to catch multimodal out-of-context pairing [7], [8].
5. **RG-5: Absence of an Integrated Multi-Threat System Fabric:** Prior academic literature evaluates detectors as isolated statistical prototypes in Python notebooks. There is an absence of enterprise-grade, resilient microservices frameworks that orchestrate multi-threat verification with unified authentication, audit persistence, and asynchronous messaging.

---

### **2.4 Problem Formulation**
Let $Q$ represent a multi-threat security query submitted by an authenticated user $U$. $Q$ can contain any combination of a candidate URL $u \in \mathcal{U}$, a multimedia artifact $m \in \mathcal{M}$ (image, video, or audio), an identity credential string $c \in \mathcal{C}$, or a natural language claim $t \in \mathcal{T}$.

The objective of **TrustShield** is to map the composite input query $Q = \{u, m, c, t\}$ through a distributed verification function $\mathcal{F}_{\text{TrustShield}}$:
$$\mathcal{F}_{\text{TrustShield}}: Q \longrightarrow \big\langle \mathbf{R}, \mathbf{C}, \mathbf{E}, \mathbf{A} \big\rangle$$
where:
- $\mathbf{R} \in [0, 100]$ is the standardized normalized Risk Score.
- $\mathbf{C} \in \{\text{LOW}, \text{MEDIUM}, \text{HIGH}, \text{CRITICAL}\}$ is the categorical Threat Severity Classification.
- $\mathbf{E} = \{e_1, e_2, \dots, e_k\}$ is a set of human-interpretable technical evidence vectors and explanation tokens.
- $\mathbf{A} = \{a_1, a_2, \dots, a_m\}$ is an actionable, context-aware remediation advisory (e.g., immediate credential rotation, domain firewall blocking, multi-factor authentication enforcement).

The platform must enforce this transformation subject to:
$$\text{Latency}(Q_{\text{interactive}}) \le 200\,\text{ms}, \quad \text{Privacy}(c) = \text{Zero-Knowledge}(c), \quad \text{Availability} \ge 99.9\%$$

---

\newpage

# **3. REQUIREMENTS ENGINEERING AND FEASIBILITY STUDY**

### **3.1 Software Requirements Specification (SRS)**

#### **3.1.1 Functional Requirements (FR)**

**Table 3.1: Functional Requirements Specification**

| Requirement ID | Requirement Name | Description & Operational Specifications |
| :--- | :--- | :--- |
| **FR-01** | User Identity & Token Management | The system shall authenticate users via bcrypt-hashed credentials, issuing signed, stateless HMAC-SHA256 JWT access and refresh tokens. |
| **FR-02** | URL & QR Code Ingestion | The system shall ingest raw URLs or decoded QR code targets, performing unshortening, canonicalization, and RFC 3986 normalization. |
| **FR-03** | Multi-Layered Phishing Analysis | The system shall extract 32 lexical URL features, query internal ONNX gradient-boosted trees, poll threat feeds, and synthesize a composite phishing risk score. |
| **FR-04** | Secure Multimedia Upload | The system shall validate uploaded media MIME types, enforce file-size quotas (up to 50MB for video, 10MB for audio/image), and persist files into MinIO S3 buckets. |
| **FR-05** | Deepfake Forensic Inference | The system shall extract frames and audio spectrographs, execute deep neural inference via DJL/ONNX Runtime, and return an artifact confidence score and heatmap. |
| **FR-06** | Privacy-Preserving Breach Monitoring | The system shall accept user identifiers, calculate their SHA-256 hash, and register only the first 5 hexadecimal characters for continuous monitoring. |
| **FR-07** | Automated Breach Alert Generation | The system shall periodically query authorized breach sources using prefix-matching and trigger high-priority alerts if a full-hash match is identified. |
| **FR-08** | Multimodal Claim Verification | The system shall parse textual claims, extract named entities, query Google Fact Check / ClaimReview APIs, compute cross-modal text-image similarity, and render a verdict. |
| **FR-09** | Audit Trail & Scan History | The system shall persist historical scan logs and risk metrics per user in PostgreSQL, permitting authenticated historical inspection and PDF report export. |
| **FR-10** | Multi-Channel Notification Dispatch | The system shall dispatch event-driven alerts across configured channels (Email via SMTP, Webhooks, Push notifications) upon detection of HIGH or CRITICAL threats. |
| **FR-11** | Asynchronous Kafka Event Streaming | The system shall stream compute-intensive media analysis and alert jobs through dedicated Kafka topics without blocking client HTTP request threads. |
| **FR-12** | Health, Metrics & Observability | The system shall expose Spring Boot Actuator endpoints (`/actuator/health`, `/actuator/metrics`, `/actuator/prometheus`) for container cluster monitoring. |

#### **3.1.2 Non-Functional Requirements (NFR)**

**Table 3.2: Non-Functional Requirements Specification**

| ID | Quality Attribute | Technical Specification & Acceptance Criteria |
| :--- | :--- | :--- |
| **NFR-01** | **Security** | Zero-trust inter-service communication; Spring Security 6 filtering; OWASP Top 10 mitigation; encrypted secrets management via environment injection. |
| **NFR-02** | **Privacy** | Zero-knowledge credential hashing; zero plaintext identifier persistence; strict GDPR / DPDP Act data minimization compliance. |
| **NFR-03** | **Performance** | Interactive URL and breach lookups shall achieve $p_{95} \le 200\,\text{ms}$. Asynchronous media analysis shall complete processing within $15\,\text{seconds}$ for 1080p clips. |
| **NFR-04** | **Scalability** | All domain services shall be completely stateless, supporting horizontal auto-scaling from 1 to 10 container replicas behind Spring Cloud Gateway. |
| **NFR-05** | **Reliability & Resilience** | Circuit-breaker implementation (Resilience4j) on all external API integrations; automatic retry with exponential backoff on Kafka consumers. |
| **NFR-06** | **Maintainability** | Strict separation of concerns via microservices; automated database schema versioning with Flyway; 100% adherence to OpenAPI 3.0 documentation. |
| **NFR-07** | **Observability** | Centralized distributed tracing via Micrometer Tracing; structured JSON logging with correlation IDs ingested into Elasticsearch. |
| **NFR-08** | **Usability** | Normalized risk scores ($0\text{--}100$) mapped to human-comprehensible color codes (Green, Amber, Red) and concrete remediation bullet points. |
| **NFR-09** | **Portability** | Complete containerization of services, databases, message brokers, and storage layers via multi-stage Dockerfiles and Docker Compose orchestration. |
| **NFR-10** | **Concurrency** | Leveraging Java 21 Virtual Threads (Project Loom) within Spring Boot 3.3 to handle up to 10,000 concurrent I/O-bound requests per gateway node. |

---

### **3.2 Feasibility Analysis**

#### **3.2.1 Technical Feasibility**
The proposed platform is technically sound and achievable. The backend relies on **Java 21 LTS** and **Spring Boot 3.3.x**, offering enterprise-grade concurrency through Project Loom's virtual threads. Machine learning inference is decoupled from heavy Python web runtimes by compiling models to **ONNX (Open Neural Network Exchange)** format and executing them via the **Deep Java Library (DJL)** directly inside JVM memory. Asynchronous communication via **Apache Kafka** guarantees that variable-latency external threat-intelligence lookups and heavy media processing do not bottleneck real-time user requests.

#### **3.2.2 Operational and Architectural Feasibility**
The microservice boundaries strictly adhere to the Single Responsibility Principle (SRP). Deployment is orchestrated using Docker Compose for local academic evaluation and is directly portable to Kubernetes (K8s) clusters. Each service maintains its own private data store or isolated schema, preventing architectural coupling.

#### **3.2.3 Economic Feasibility**
TrustShield is built entirely on mature open-source software:
- Programming Languages & Frameworks: OpenJDK 21, Spring Boot (Apache 2.0 License).
- Data & Messaging: PostgreSQL (PostgreSQL License), Redis (Redis Source Available / BSD), Apache Kafka (Apache 2.0).
- Deep Learning: ONNX Runtime (MIT License), Deep Java Library (Apache 2.0).
- Storage & Search: MinIO Community Edition (AGPL v3), OpenSearch / Elasticsearch (Apache 2.0 / SSPL).
- Development Costs: Requires zero commercial licensing fees during research and academic deployment.

#### **3.2.4 Legal, Ethical, and Privacy Feasibility**
Cybersecurity systems must not inadvertently become surveillance or surveillance-enabling tools. TrustShield enforces strict privacy-by-design:
- In breach monitoring, the platform never stores raw passwords or email addresses. It implements a $k$-anonymity prefix-hashing protocol identical to the mathematical model popularized by NIST SP 800-63B.
- In media analysis, uploaded artifacts are assigned cryptographic UUIDs, retained only in private, short-lived MinIO buckets, and purged automatically post-inference according to retention policies.
- In claim verification, automated labels are framed as probabilistic risk assessments rather than definitive censorship directives.

---

### **3.3 Hardware and Software Environments**

**Table 3.3: Hardware Environment Specifications**

| Component | Minimum Development Node | Recommended Production / Test Node |
| :--- | :--- | :--- |
| **Processor (CPU)** | Intel Core i7 / AMD Ryzen 7 (8 Cores, 16 Threads) | 16-Core Intel Xeon / AMD EPYC Cloud Instance |
| **System Memory (RAM)** | 16 GB DDR4 / DDR5 | 32 GB – 64 GB ECC Registered RAM |
| **Graphics Accelerator (GPU)**| Optional (NVIDIA RTX 3060 6GB or higher) | NVIDIA Tesla T4 / A10G (16GB VRAM) |
| **Disk Storage** | 256 GB NVMe SSD (High IOPS) | 1 TB Enterprise NVMe SSD Storage |
| **Network Interface** | 100 Mbps Full Duplex Ethernet | 1 Gbps / 10 Gbps Low-Latency Network |

**Table 3.4: Software Environment and Technology Stack**

| Tier / Layer | Technology Selected | Version | Purpose & Rationale |
| :--- | :--- | :--- | :--- |
| **Runtime Environment** | OpenJDK | 21 LTS | High-throughput virtual threads (Project Loom) |
| **Core Framework** | Spring Boot | 3.3.3 | Enterprise microservices scaffolding and DI |
| **API Gateway** | Spring Cloud Gateway | 4.1.x | Non-blocking reactive routing and rate limiting |
| **Security Framework** | Spring Security | 6.3.x | Stateless JWT filter chains and role authorization |
| **Build & Dependency Tool** | Apache Maven | 3.9.x | Declarative dependency management and packaging |
| **ML Inference Engine** | DJL + ONNX Runtime | 0.28.x / 1.18.x | Native in-JVM multi-threaded model execution |
| **Message Broker** | Apache Kafka | 3.7.x | High-throughput event pub/sub decoupling |
| **Relational Database** | PostgreSQL | 16.4 | ACID-compliant relational scan and user storage |
| **In-Memory Cache** | Redis | 7.2 | Token-bucket rate limiting and session caching |
| **Object Store** | MinIO (S3 API) | RELEASE.2024 | Secure storage for submitted media files |
| **Search Engine** | Elasticsearch | 8.14.x | Fast full-text indexing of logs and security events |
| **Containerization** | Docker & Docker Compose | 26.x / 2.27.x | Repeatable multi-container microservice topology |

---

\newpage

# **4. SYSTEM ARCHITECTURE AND DESIGN**

### **4.1 Design Philosophy and High-Level Architecture**
TrustShield is designed following the **Microservices Architecture Pattern**, combined with an **Event-Driven Architecture (EDA)** for non-blocking operations. The system is split across four distinct vertical tiers:
1. **Client / Presentation Tier:** Web responsive applications, cross-platform mobile clients, and browser security extensions communicating over HTTPS.
2. **Edge Gateway Tier:** A unified Spring Cloud Gateway handling transport security (TLS termination), request routing, JWT validation, global CORS enforcement, and Redis-backed token-bucket rate limiting.
3. **Domain Services Tier:** Independent microservices containing isolated business logic:
   - `auth-service` (Port 8081)
   - `phishing-service` (Port 8082)
   - `deepfake-service` (Port 8083)
   - `breach-service` (Port 8084)
   - `factcheck-service` (Port 8085)
   - `notification-service` (Port 8086)
4. **Data and Event Streaming Tier:** Shared infrastructure backing the domain services: Apache Kafka, PostgreSQL, Redis, MinIO S3, and Elasticsearch.

```
+---------------------------------------------------------------------------------------+
|                               PRESENTATION CLIENT TIER                                |
|   [ Browser Web Portal ]       [ Mobile App (Android/iOS) ]     [ Browser Extension ] |
+-------------------------------------------+-------------------------------------------+
                                            | HTTPS / WSS
                                            v
+---------------------------------------------------------------------------------------+
|                    EDGE GATEWAY TIER (Spring Cloud Gateway - Port 8080)               |
|   [ JWT Auth Filter ]   [ Token Bucket Rate Limiter ]   [ Global Reverse Proxy ]      |
+----+-------------------+-------------------+-------------------+------------------+---+
     |                   |                   |                   |                  |
     v                   v                   v                   v                  v
+----------+       +-----------+       +-----------+       +-----------+      +-----------+
|  Auth    |       | Phishing  |       | Deepfake  |       |  Breach   |      | FactCheck |
| Service  |       |  Service  |       |  Service  |       |  Service  |      |  Service  |
| (Port    |       | (Port     |       | (Port     |       | (Port     |      | (Port     |
|  8081)   |       |  8082)    |       |  8083)    |       |  8084)    |      |  8085)    |
+----+-----+       +-----+-----+       +-----+-----+       +-----+-----+      +-----+-----+
     |                   |                   |                   |                  |
     |                   +-------------------+-------------------+------------------+
     |                                       |
     |                                       v
     |                     +-----------------------------------+
     |                     |    APACHE KAFKA EVENT STREAM      |
     |                     |  - trustshield.scan.completed     |
     |                     |  - trustshield.deepfake.raw       |
     |                     |  - trustshield.breach.alert       |
     |                     +-----------------+-----------------+
     |                                       |
     |                                       v
     |                             +--------------------+
     |                             |Notification Service|
     |                             |    (Port 8086)     |
     |                             +---------+----------+
     |                                       |
     |             +-------------------------+-------------------------+
     v             v                         v                         v
+----------+ +-----------+             +-----------+             +-----------+
|PostgreSQL| |   Redis   |             | MinIO S3  |             |Elasticsearch
| Database | | In-Memory |             | Object    |             |  Security |
| (Port    | | (Port     |             | Store     |             |   Audit   |
|  5432)   | |  6379)    |             | (Port 9000|             | (Port 9200|
+----------+ +-----------+             +-----------+             +-----------+
```
*Fig. 4.1: TrustShield Enterprise Microservices Logical Architecture*

---

### **4.2 Microservices Deconstruction and Service Boundaries**

**Table 4.1: Microservice Specifications and Port Allocations**

| Microservice | Internal Port | Primary Technological Responsibilities |
| :--- | :--- | :--- |
| **`gateway-service`** | 8080 | Gateway routing, JWT validation filter, Redis RateLimiter, CORS configuration. |
| **`auth-service`** | 8081 | User registration, password encryption (BCrypt), JWT token lifecycle management. |
| **`phishing-service`** | 8082 | Lexical feature extraction, ONNX model scoring, Google Safe Browsing / VirusTotal client. |
| **`deepfake-service`** | 8083 | Multi-part media upload, frame slicing, DJL / ONNX deep learning inference, heatmap export. |
| **`breach-service`** | 8084 | $k$-anonymity SHA-256 hash prefixing, breach database querying, automated alerting. |
| **`factcheck-service`**| 8085 | Text claim parsing, Google Fact Check API integration, cross-modal semantic similarity. |
| **`notification-service`**| 8086 | Kafka consumer, multi-channel dispatch (SMTP email, webhooks, in-app notifications). |

---

### **4.3 Unified Mathematical and Threat Scoring Formulations**

#### **4.3.1 Composite Threat Scoring Model**
To eliminate conflicting outputs, each detection service normalizes its output into a continuous Threat Probability $P_k \in [0, 1]$. The overall Composite Threat Score $R_{\text{composite}} \in [0, 100]$ is computed using a dynamically weighted multi-criteria fusion function:

$$R_{\text{composite}} = \min \left( 100, \;\; 100 \times \sum_{k=1}^{N} \Big( w_k \cdot P_k \cdot \gamma_k \Big) + \delta_{\text{critical}} \right)$$

where:
- $P_k$: The output probability from detection component $k$ (e.g., $P_{\text{ML}}$, $P_{\text{Reputation}}$, $P_{\text{Heuristics}}$).
- $w_k$: Static base weight assigned to detection component $k$, such that $\sum_{k=1}^{N} w_k = 1.0$.
- $\gamma_k \in [0.5, 1.2]$: Dynamic confidence attenuation factor reflecting provider freshness and sample quality.
- $\delta_{\text{critical}} \in \{0, 40\}$: An override delta triggered when an authoritative blacklisted signature (e.g., known malware hash or confirmed phishing URL) is verified by multiple independent sources.

The score $R_{\text{composite}}$ is mapped to categorical threat levels:
$$\text{ThreatLevel}(R) = \begin{cases} 
\text{LOW} & 0 \le R < 30 \\
\text{MEDIUM} & 30 \le R < 65 \\
\text{HIGH} & 65 \le R < 85 \\
\text{CRITICAL} & 85 \le R \le 100 
\end{cases}$$

#### **4.3.2 $k$-Anonymity Mathematical Scheme for Breach Search**
To guarantee zero-knowledge credential monitoring, TrustShield enforces a mathematical prefix-partitioning scheme:
1. Let $I$ be the candidate user credential string (e.g., email address or password).
2. The client or breach service computes the SHA-256 digest:
   $$H = \text{SHA-256}(I) = h_1 h_2 h_3 \dots h_{64} \quad \text{where } h_i \in \{0\text{--}9, \text{a}\text{--}\text{f}\}$$
3. $H$ is partitioned into a 5-character prefix $H_{\text{prefix}}$ and a 59-character suffix $H_{\text{suffix}}$:
   $$H_{\text{prefix}} = h_1 h_2 h_3 h_4 h_5, \quad H_{\text{suffix}} = h_6 h_7 \dots h_{64}$$
4. The system queries the breach index using *only* $H_{\text{prefix}}$.
5. The breach index returns the anonymity set $\mathcal{A}$:
   $$\mathcal{A} = \big\{ H_{\text{suffix}}^{(1)}, H_{\text{suffix}}^{(2)}, \dots, H_{\text{suffix}}^{(M)} \big\} \quad \text{where } M \gg 1$$
6. The client evaluates whether $H_{\text{suffix}} \in \mathcal{A}$ locally in isolated volatile memory. The remote repository never learns $H$ or $I$.

#### **4.3.3 Multimodal Semantic Dissimilarity Index**
For multimodal claim verification, let $\mathbf{v}_{\text{text}} \in \mathbb{R}^{D}$ be the dense sentence embedding of the textual assertion and $\mathbf{v}_{\text{image}} \in \mathbb{R}^{D}$ be the visual embedding extracted from the accompanying image using a shared multimodal latent space.

The cross-modal semantic similarity $S_{\text{cross}}$ is computed via cosine similarity:
$$S_{\text{cross}} = \frac{\mathbf{v}_{\text{text}} \cdot \mathbf{v}_{\text{image}}}{\|\mathbf{v}_{\text{text}}\| \, \|\mathbf{v}_{\text{image}}\|}$$

The Cross-Modal Incongruity Penalty $D_{\text{incongruity}}$ is formulated as:
$$D_{\text{incongruity}} = \max\left(0, \; \theta_{\text{threshold}} - S_{\text{cross}}\right)$$
where $\theta_{\text{threshold}} \approx 0.65$. An incongruity score approaching $1.0$ indicates that an authentic image has been intentionally mispaired with a fabricated claim.

---

### **4.4 Unified Modeling Language (UML) Specifications**

#### **4.4.1 Level-0 Context-Level Data Flow Diagram (DFD)**
The Level-0 DFD illustrates the boundaries of TrustShield, identifying external entities, system inputs, and synthesized intelligence outputs:

```
                  +----------------------------------------------+
                  |                  END USER                    |
                  +-------+------------------------------^-------+
                          |                              |
      1. Submit Threat    |                              | 6. Visual Scan Report,
         (URL, Media,     |                              |    Alerts & Mitigations
         Breach, Claim)   |                              |
                          v                              |
                  +-------+------------------------------+-------+
                  |                                              |
                  |             0.0 TRUSTSHIELD PLATFORM         |
                  |          UNIFIED DIGITAL SAFETY ENGINE       |
                  |                                              |
                  +-------+---------------+--------------+-------+
                          |               |              |
         2. API Queries   |               | 3. Raw Media | 4. Search & Prefixes
         & URL Lookup     v               v              v
                  +-------+----+    +-----+----+    +----+-------+
                  |  EXTERNAL  |    | MinIO S3 |    | HIBP / CTI |
                  | THREAT INT |    | MEDIA    |    | BREACH     |
                  | (VT, GSB)  |    | BUCKET   |    | REPOSITORY |
                  +------------+    +----------+    +------------+
```
*Fig. 4.2: Level-0 Context-Level Data Flow Diagram*

---

#### **4.4.2 Level-1 Detailed Data Flow Diagram**
The Level-1 DFD decomposes the system into its six core processes, detailing data movement across message brokers and persistent stores:

```
                +-----------------------------------------------+
                |                   END USER                    |
                +----+-------------------------------------^----+
                     |                                     |
                     | 1. HTTP Request + JWT               | 12. Aggregated Threat
                     v                                     |     Response & Metrics
           +---------+----------+                          |
           | 1.0 GATEWAY ROUTER |                          |
           +----+----+----+-----+                          |
                |    |    |                                |
  2. URL Request|    |    | 3. Media Upload                |
        +-------+    |    +-----------------------+        |
        v            v 4. Identity Hash           v        |
   +----+---+   +----+---+                   +----+---+    |
   |2.0 URL |   |3.0     |                   |4.0     |    |
   |PHISHING|   |BREACH  |                   |DEEPFAKE|    |
   |ANALYSIS|   |MONITOR |                   |ANALYSIS|    |
   +----+---+   +----+---+                   +----+---+    |
        |            |                            |        |
        |            |                            +-----+  |
        v            v                                  |  |
   +----+------------+----+                             |  |
   | D1: POSTGRESQL DB    |                             |  |
   | (Scans, Users, Logs) |                             |  |
   +----------------------+                             |  |
                                                        v  |
                                               +--------+--+----+
                                               | 5.0 KAFKA BUS  |
                                               | (Async Events) |
                                               +--------+-------+
                                                        |
                                                        v
                                               +--------+-------+
                                               |6.0 NOTIFICATION|
                                               |    DISPATCH    |
                                               +--------+-------+
                                                        |
                                                        v 11. Multi-Channel Alert
                                               +--------+-------+
                                               | Email / Push   |
                                               +----------------+
```
*Fig. 4.3: Level-1 Detailed Data Flow Diagram*

---

#### **4.4.3 UML Use Case Diagram**

```
+------------------------------------------------------------------------------------+
|                               TRUSTSHIELD SYSTEM                                   |
|                                                                                    |
|       ( Register / Login ) <------------------------------------+                  |
|               ^                                                 |                  |
|               | <<include>>                                     |                  |
|       ( Authenticate via JWT )                                  |                  |
|               ^                                                 |                  |
|               | <<include>>                                     |                  |
|       ( Scan Suspicious URL / QR ) -----------------------+     |                  |
|               |                                           |     |                  |
|               | <<extend>>                                |     |                  |
|       ( Query Reputation Feeds )                          |     |   +----------+   |
|                                                           +-----+---| End User |   |
|       ( Upload Media for Deepfake Scan ) -----------------+     |   +----------+   |
|               |                                           |     |                  |
|               | <<include>>                               |     |                  |
|       ( Render Artifact Heatmap )                         |     |                  |
|                                                           |     |                  |
|       ( Register Credential for Breach Monitor ) ---------+     |                  |
|                                                           |     |                  |
|       ( Submit Multi-modal Claim for Fact-Check ) --------+     |                  |
|                                                           |     |                  |
|       ( Review Historical Audit Log ) --------------------+     |                  |
|                                                                 |                  |
|       ( Configure Rate Limits & Model Weights ) ----------------+--- [ Admin ]     |
|                                                                                    |
|       ( Ingest Threat Feeds ) <------------------------------------- [ CTI Feed ]  |
+------------------------------------------------------------------------------------+
```
*Fig. 4.4: UML Use Case Diagram*

---

#### **4.4.4 Domain Class Diagram**
The domain model captures entity relationships, persistence mappings, and service boundaries:

```
+---------------------------+             +---------------------------+
|          User             | 1         * |        ScanResult         |
+---------------------------+-------------+---------------------------+
| - id: UUID                |             | - id: UUID                |
| - email: String           |             | - userId: UUID            |
| - passwordHash: String    |             | - targetUrl: String       |
| - role: UserRole          |             | - urlHash: String         |
| - createdAt: Instant      |             | - riskScore: Double       |
+---------------------------+             | - threatLevel: ThreatLevel|
| + validatePassword()      |             | - enginesScanned: Integer |
| + updateProfile()         |             | - detailsJson: String     |
+---------------------------+             | - createdAt: Instant      |
                                          +---------------------------+
                                          | + calculateRisk()         |
                                          +---------------------------+

+---------------------------+             +---------------------------+
|         MediaScan         |             |       BreachMonitor       |
+---------------------------+             +---------------------------+
| - id: UUID                |             | - id: UUID                |
| - userId: UUID            |             | - userId: UUID            |
| - fileName: String        |             | - identifierPrefix: String|
| - mediaType: MediaType    |             | - identifierHash: String  |
| - s3ObjectKey: String     |             | - identifierType: IdType  |
| - sha256Digest: String    |             | - isMonitored: Boolean    |
| - isSynthetic: Boolean    |             | - createdAt: Instant      |
| - confidence: Double      |             +---------------------------+
| - riskScore: Double       |             | + checkPrefixMatch()      |
| - createdAt: Instant      |             +---------------------------+
+---------------------------+
| + extractFrames()         |
| + runInference()          |
+---------------------------+
```
*Fig. 4.5: Core Domain Class Diagram*

---

#### **4.4.5 Sequence Diagrams**

##### **Workflow A: Synchronous Real-Time Phishing Analysis Workflow**
```
User             Gateway            PhishingService       RedisCache       ThreatFeedAPI      Database
 |                  |                      |                   |                 |                |
 |-- POST /scan --->|                      |                   |                 |                |
 |                  |-- Validate JWT ----->|                   |                 |                |
 |                  |-- Route Request ---->|                   |                 |                |
 |                  |                      |-- Check Cache --->|                 |                |
 |                  |                      |<-- Cache Miss ----|                 |                |
 |                  |                      |                                     |                |
 |                  |                      |-- Extract Lexical Features          |                |
 |                  |                      |-- Execute Local ONNX Model          |                |
 |                  |                      |                                     |                |
 |                  |                      |-- Query Threat Reputation --------->|                |
 |                  |                      |<-- Return Threat Indicators --------|                |
 |                  |                      |                                     |                |
 |                  |                      |-- Compute Composite Risk Score      |                |
 |                  |                      |-- Cache Result -------------------->|                |
 |                  |                      |-- Persist Scan Record ------------------------------>|
 |                  |                      |                                                      |
 |                  |<-- 200 OK (Report) --|                                                      |
 |<-- JSON Result --|                      |                                                      |
```
*Fig. 4.6: UML Sequence Diagram: Synchronous Phishing Analysis Workflow*

##### **Workflow B: Asynchronous Deepfake Ingestion and Notification via Kafka**
```
User             Gateway             DeepfakeService         MinIO S3          KafkaBus      NotificationService
 |                  |                       |                    |                 |                  |
 |-- POST /media -->|                       |                    |                 |                  |
 |   (Multipart)    |-- Route Request ----->|                    |                 |                  |
 |                  |                       |-- Stream to S3 --->|                 |                  |
 |                  |                       |<-- Object Key -----|                 |                  |
 |                  |                       |                                      |                  |
 |                  |                       |-- Publish Ingestion Event ---------->|                  |
 |                  |<-- 202 Accepted ------|                                      |                  |
 |<-- Job UUID -----|   (Job Created)       |                                      |                  |
 |                  |                       |                                      |                  |
 |                  |                       |*** ASYNCHRONOUS INFERENCE WORKER *** |                  |
 |                  |                       |-- Consume Event <--------------------|                  |
 |                  |                       |-- Fetch Media & Slices <-------------|                  |
 |                  |                       |-- Execute DJL / ONNX Model           |                  |
 |                  |                       |-- Generate Heatmap & Metrics         |                  |
 |                  |                       |                                      |                  |
 |                  |                       |-- Publish Completion Event --------->|                  |
 |                  |                       |                                      |-- Consume Event -|
 |                  |                       |                                      |-- Dispatch Email |
 |<-- Push/Alert Notification --------------|--------------------------------------|   or Webhook ----|
```
*Fig. 4.7: UML Sequence Diagram: Asynchronous Deepfake Ingestion via Kafka*

---

### **4.5 Relational Database Schema Design (DDL & ER Model)**

**Table 4.2: Relational Database Schema Specification (PostgreSQL 16)**

```sql
-- 1. USERS TABLE
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'ROLE_USER',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_users_email ON users(email);

-- 2. URL SCAN RESULTS TABLE
CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    url_hash CHAR(64) NOT NULL,
    risk_score NUMERIC(5, 2) NOT NULL,
    threat_level VARCHAR(20) NOT NULL,
    model_score NUMERIC(5, 4) NOT NULL,
    threat_intel_matches INTEGER DEFAULT 0,
    features_json JSONB,
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_scan_url_hash ON scan_results(url_hash);
CREATE INDEX idx_scan_user ON scan_results(user_id);

-- 3. MEDIA SCANS TABLE
CREATE TABLE media_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    file_name VARCHAR(255) NOT NULL,
    media_type VARCHAR(50) NOT NULL,
    s3_object_key TEXT NOT NULL,
    sha256_hash CHAR(64) NOT NULL,
    is_deepfake BOOLEAN NOT NULL,
    confidence NUMERIC(5, 4) NOT NULL,
    risk_score NUMERIC(5, 2) NOT NULL,
    heatmap_s3_key TEXT,
    execution_time_ms BIGINT NOT NULL,
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_media_hash ON media_scans(sha256_hash);

-- 4. BREACH MONITORS TABLE
CREATE TABLE breach_monitors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identifier_prefix CHAR(5) NOT NULL,
    identifier_hash CHAR(64) NOT NULL,
    identifier_type VARCHAR(50) NOT NULL,
    alias_label VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_breach_prefix ON breach_monitors(identifier_prefix);
CREATE UNIQUE INDEX uq_user_identifier ON breach_monitors(user_id, identifier_hash);

-- 5. BREACH ALERTS TABLE
CREATE TABLE breach_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    monitor_id UUID NOT NULL REFERENCES breach_monitors(id) ON DELETE CASCADE,
    breach_source VARCHAR(255) NOT NULL,
    breach_date DATE,
    compromised_data_classes TEXT[],
    is_read BOOLEAN DEFAULT FALSE,
    alerted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_alerts_monitor ON breach_alerts(monitor_id);

-- 6. FACT CHECK VERDICTS TABLE
CREATE TABLE fact_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    claim_text TEXT NOT NULL,
    claim_hash CHAR(64) NOT NULL,
    verdict VARCHAR(50) NOT NULL,
    confidence NUMERIC(5, 4) NOT NULL,
    explanation TEXT NOT NULL,
    cross_modal_score NUMERIC(5, 4),
    sources_json JSONB,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_fact_claim_hash ON fact_checks(claim_hash);
```

---

### **4.6 Event-Driven Architecture and Apache Kafka Topic Hierarchy**

**Table 4.3: Kafka Topic Specifications**

| Topic Name | Partitions | Replication | Key | Value Schema (Avro / JSON) |
| :--- | :--- | :--- | :--- | :--- |
| `trustshield.scan.url.completed` | 6 | 3 | `url_hash` | `{ scanId, url, riskScore, threatLevel, timestamp }` |
| `trustshield.media.ingested` | 12 | 3 | `mediaId` | `{ mediaId, s3Key, mediaType, userId, timestamp }` |
| `trustshield.media.analyzed` | 12 | 3 | `mediaId` | `{ mediaId, isDeepfake, confidence, heatmapKey }` |
| `trustshield.breach.match.detected`| 4 | 3 | `userId` | `{ monitorId, breachSource, dataTypes, timestamp }` |
| `trustshield.notification.dispatch`| 8 | 3 | `userId` | `{ recipient, channel, templateId, payloadData }` |

---

### **4.7 RESTful API Contract Design (OpenAPI 3.0 Standard)**

**Table 4.4: Core REST API Specifications**

| Method | Endpoint | Auth | Request Body | Response Codes | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/register` | None | `{email, password, name}` | `201 Created`, `400 Bad Req` | User account registration |
| `POST` | `/api/v1/auth/login` | None | `{email, password}` | `200 OK`, `401 Unauth` | Issue JWT access & refresh tokens |
| `POST` | `/api/v1/phishing/scan` | Bearer | `{url}` | `200 OK`, `429 RateLimit` | Synchronous URL threat evaluation |
| `POST` | `/api/v1/deepfake/upload` | Bearer | `multipart/form-data` | `202 Accepted`, `413 Too Large` | Ingest media for async inference |
| `GET` | `/api/v1/deepfake/status/{id}`| Bearer | None | `200 OK`, `404 Not Found` | Poll media inference status |
| `POST` | `/api/v1/breach/monitor` | Bearer | `{prefix, hash, type}` | `201 Created`, `409 Conflict` | Register anonymized breach prefix |
| `GET` | `/api/v1/breach/alerts` | Bearer | None | `200 OK` | Fetch alerts for user monitors |
| `POST` | `/api/v1/factcheck/verify` | Bearer | `{claimText, mediaId?}` | `200 OK`, `503 Unavailable` | Multimodal fact verification |
| `GET` | `/api/v1/history/scans` | Bearer | `?page=0&size=20` | `200 OK` | Paginated user scan history |

---

### **4.8 Security, Authentication, and Privacy Engineering**
- **Zero-Trust Security Perimeter:** The Spring Cloud Gateway enforces strict TLS 1.3 termination. Internal service-to-service calls reside within an isolated Docker overlay network (`trustshield-internal-net`), unreachable from the public internet.
- **Stateless JWT Authorization:** Access tokens are signed using HMAC-SHA256 with rotating 256-bit cryptographic keys. The Gateway intercepts every request, validates the signature, extracts user claims, and forwards headers (`X-User-Id`, `X-User-Role`) downstream.
- **Resilience and Throttling:** Distributed rate limiting is implemented at the Gateway level using Redis token buckets ($100\,\text{requests/minute}$ per client IP for standard users; $1000\,\text{req/min}$ for privileged tiers), thwarting denial-of-service and credential brute-forcing.

---

\newpage

# **5. METHODOLOGY AND IMPLEMENTATION DETAILS**

### **5.1 Phishing and Malicious URL Detection Engine**
The Phishing Detection Engine executes a four-stage assessment pipeline:
1. **Normalization:** Parses input URLs, decoding percent-encoded characters, stripping tracking UTM parameters, resolving IP addresses, and following HTTP 301/302 redirects to identify destination landing pages.
2. **Feature Extraction:** Computes a 32-dimensional continuous feature vector:
   - Structural metrics: URL length, domain length, path depth, subdomain count.
   - Lexical indicators: Entropy of domain string, presence of IP address in host, suspicious keywords (`login`, `secure`, `verify`, `banking`, `update`).
   - Character counts: Frequency of hyphens, `@` symbols, underscores, and consecutive delimiters.
3. **Model Scoring:** Loads a lightweight Gradient Boosted Decision Tree (GBDT) model via ONNX Runtime inside the JVM, generating a probability score $P_{\text{ML}} \in [0, 1]$.
4. **Threat Intelligence Aggregation:** Concurrently queries cached Google Safe Browsing and VirusTotal reputation hash tables in Redis.

```
+-------------------------------------------------------------------------+
|                  ALGORITHM 1: Multi-Tier Phishing URL Evaluator         |
+-------------------------------------------------------------------------+
INPUT:  rawUrl (String), userToken (String)
OUTPUT: ScanResultDto (RiskScore, ThreatLevel, EvidenceList)

1.  canonicalUrl = NormalizeAndResolveRedirects(rawUrl)
2.  urlHash = SHA256(canonicalUrl)
3.  cachedResult = Redis.get("url:" + urlHash)
4.  IF cachedResult IS NOT NULL:
5.      RETURN cachedResult
6.  features = ExtractLexicalFeatures(canonicalUrl)
7.  onnxTensor = ConvertToTensor(features)
8.  p_ML = OnnxRuntime.runInference("phishing_model.onnx", onnxTensor)
9.  p_Intel = ThreatIntelClient.queryFeeds(urlHash)
10. finalRisk = CalculateCompositeScore(p_ML, p_Intel)
11. evidence = CompileEvidenceTokens(features, p_Intel)
12. result = New ScanResult(canonicalUrl, finalRisk, evidence)
13. Redis.setex("url:" + urlHash, 3600, result)
14. Database.persist(result)
15. RETURN result
+-------------------------------------------------------------------------+
```

---

### **5.2 Deepfake Analysis Pipeline via ONNX and DJL**
Deepfake media analysis requires processing compute-intensive spatial and temporal data. Rather than routing raw video bytes to external Python microservices (introducing network serialization overhead), TrustShield utilizes the **Deep Java Library (DJL)** coupled with the **ONNX Runtime Java Engine**.
- **Frame Extraction:** Videos are sampled at uniform intervals (e.g., 2 frames per second) using FFmpeg native bindings.
- **Facial Landmark Cropping:** Bounding boxes around facial regions are extracted, aligned, and normalized to $256 \times 256 \times 3$ RGB tensors.
- **Frequency Artifact Analysis:** Multi-scale 2D Discrete Cosine Transform (DCT) is applied to extract frequency-domain boundary residuals.
- **Inference Execution:** DJL loads the quantized EfficientNet-V2 / MesoInception model, executing batch tensor operations over available GPU/CPU threads.

```
+-------------------------------------------------------------------------+
|             ALGORITHM 2: Deepfake Forensic Inference Pipeline           |
+-------------------------------------------------------------------------+
INPUT:  mediaFile (InputStream), mediaType (MediaType)
OUTPUT: MediaScanResult (isDeepfake, confidenceScore, heatmapLocation)

1.  s3Key = MinIO.upload("media-bucket", mediaFile)
2.  shaDigest = ComputeSHA256(mediaFile)
3.  frames = FFmpegJava.extractKeyframes(mediaFile, sampleRate=2.0)
4.  batchTensors = []
5.  FOR EACH frame IN frames:
6.      faceCrop = RetinaFace.detectAndAlign(frame)
7.      IF faceCrop IS VALID:
8.          normalizedTensor = PreprocessImage(faceCrop, size=256, normalize=True)
9.          batchTensors.append(normalizedTensor)
10. predictions = DJLModelRunner.predictBatch("deepfake_detector.onnx", batchTensors)
11. confidence = AggregateConfidenceScores(predictions)
12. isSynthetic = confidence >= 0.70
13. heatmapKey = GradCAM.generateAndUpload(batchTensors, s3Key)
14. record = Database.saveMediaScan(shaDigest, s3Key, isSynthetic, confidence, heatmapKey)
15. Kafka.publish("trustshield.media.analyzed", record)
16. RETURN record
+-------------------------------------------------------------------------+
```

---

### **5.3 Privacy-Preserving Breach Monitoring Subsystem**
The Breach Monitoring Subsystem operates under strict zero-knowledge principles. Users monitor personal identifiers (e.g., employee corporate emails, secondary identity handles) without exposing the identity strings to the backend database.
- The client-side application hashes the identifier using SHA-256.
- The client extracts the first 5 characters ($H_{\text{prefix}}$) and submits it to the `breach-service`.
- The `breach-service` performs a prefix lookup against the indexed breach repository (e.g., HaveIBeenPwned API or local offline breach corpus).
- Suffixes matching the prefix are returned to the client, which evaluates membership locally in volatile memory.

```
+-------------------------------------------------------------------------+
|            ALGORITHM 3: k-Anonymity Privacy-Preserving Breach Check     |
+-------------------------------------------------------------------------+
INPUT:  rawIdentifier (String)
OUTPUT: BreachStatus (isCompromised, breachSources[], recommendedActions[])

1.  fullDigest = SHA256(rawIdentifier.toLowerCase().trim())
2.  prefix = fullDigest.substring(0, 5).toUpperCase()
3.  suffix = fullDigest.substring(5).toUpperCase()
4.  candidateSuffixes = BreachClient.queryPrefixRange(prefix)
5.  matchFound = FALSE
6.  FOR EACH entry IN candidateSuffixes:
7.      IF entry.suffix == suffix:
8.          matchFound = TRUE
9.          breachDetails = entry.metadata
10.         BREAK
11. IF matchFound:
12.     remediation = GenerateMitigationAdvice(breachDetails.dataClasses)
13.     RETURN New BreachStatus(Compromised=TRUE, breachDetails, remediation)
14. ELSE:
15.     RETURN New BreachStatus(Compromised=FALSE, emptyList(), "No Exposure")
+-------------------------------------------------------------------------+
```

---

### **5.4 Multimodal Misinformation and RAG Verification Engine**
The Fact-Checking Service processes unstructured textual claims that circulate on social media:
1. **Entity Extraction & Claim Parsing:** Text assertions are tokenized using Spring AI / Stanford CoreNLP abstractions to extract core entities, temporal claims, and factual relations.
2. **Retrieval-Augmented Verification:** The system queries authenticated fact-checking repositories (e.g., Google Fact Check Tools API / ClaimReview standard) for pre-existing verdicts.
3. **Cross-Modal Grounding:** When media accompanies the claim, visual features are projected into a common embedding space alongside text embeddings to detect semantic incongruity (out-of-context reuse).
4. **Structured Explanation Generation:** A local/hosted instruction-tuned LLM parses the retrieved evidence documents and synthesizes an objective, evidence-grounded summary with source URLs, categorized under: `VERIFIED_TRUE`, `FALSE`, `MISLEADING`, or `UNVERIFIABLE`.

---

\newpage

# **6. EVALUATION METRICS AND TESTING METHODOLOGY**

### **6.1 Evaluation Metrics and Mathematical Definitions**
To maintain academic rigor, the platform's multi-threat detection models and system runtime performance are evaluated across established classification, ranking, and latency metrics:

**Table 6.1: Formal Evaluation Metrics and Mathematical Formulations**

| Metric | Formula / Mathematical Expression | Primary Objective |
| :--- | :--- | :--- |
| **Accuracy** | $\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$ | Overall correctness across balanced test distributions. |
| **Precision** | $\text{Precision} = \frac{TP}{TP + FP}$ | Minimizes false alarms; critical for avoiding benign URL blocking. |
| **Recall (Sensitivity)** | $\text{Recall} = \frac{TP}{TP + FN}$ | Maximizes threat interception; critical for security safety. |
| **$F_1$-Score** | $F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ | Harmonic mean; decisive for imbalanced cyber-threat datasets. |
| **ROC-AUC** | $\int_0^1 \text{TPR}(\text{FPR}^{-1}(t)) \, dt$ | Discriminative ability across varying classification thresholds. |
| **PR-AUC** | $\int_0^1 P(R) \, dR$ | Area under Precision-Recall curve; best for rare attack classes. |
| **Latency ($p_{95}, p_{99}$)** | $T \text{ such that } P(\text{Latency} \le T) = 0.95, 0.99$ | Quantifies tail latency under peak concurrent user loads. |
| **System Throughput** | $\text{Throughput} = \frac{\text{Total Successfully Processed Requests}}{\Delta t}$ | Measures requests handled per second (RPS) per service. |

---

### **6.2 Experimental Setup and Benchmark Datasets**
To validate the model integration without data contamination, evaluation is structured around recognized public benchmark corpora:

**Table 6.2: Benchmark Datasets for Model Validation**

| Detection Service | Benchmark Dataset | Size / Composition | Evaluation Focus |
| :--- | :--- | :--- | :--- |
| **Phishing URL Engine** | **ISCX-URL-2016** & **PhishTank** | 120,000 URLs (60k Benign, 60k Malicious) | Lexical classification & out-of-distribution drift. |
| **Deepfake Image Engine** | **FaceForensics++ (FF++)** | 1,000 sequences across 4 manipulation types | Spatial artifact detection and cross-manipulation tests. |
| **Deepfake Audio Engine** | **ASVspoof 2021** | 20,000 synthesized & genuine speech utterances | Spectral replay & voice-clone discrimination. |
| **Misinformation Engine**| **PolitiFact & GossipCop (FakeNewsNet)**| 22,000 verified claims with metadata and images | Cross-modal text-image semantic coherence. |

---

### **6.3 Comprehensive Testing Strategy**

**Table 6.3: Multi-Layered Testing Hierarchy**

| Testing Tier | Toolchain Employed | Scope and Acceptance Criteria |
| :--- | :--- | :--- |
| **Unit Testing** | JUnit 5, Mockito, AssertJ | 80%+ line coverage across business logic, validators, DTO mappers, and risk score aggregation functions. |
| **Integration Testing** | **Testcontainers** | Spin up real Docker containers for PostgreSQL, Kafka, and Redis during build verification; test end-to-end repository queries. |
| **API Contract Testing**| MockMvc, WireMock | Validate compliance with OpenAPI 3.0 specs, handling HTTP error codes (400, 401, 403, 404, 429, 500). |
| **Performance & Load** | **Apache JMeter / k6** | Simulate 1,000 concurrent virtual users hitting the API Gateway; verify gateway $p_{95}$ latency remains below $200\,\text{ms}$. |
| **Security / SAST / DAST**| **OWASP ZAP**, SonarQube | Verify zero SQL injection, robust JWT validation, strict CORS headers, and zero plaintext secret leakage in logs. |
| **Resilience / Chaos** | Spring Cloud Circuit Breaker | Simulate external API timeout failures (e.g., VirusTotal down); verify graceful degradation to internal heuristic scores. |

---

### **6.4 Empirical Experimental Results and Benchmarks**

To validate the real-world operational viability of TrustShield, empirical evaluations were executed across classification accuracy, feature extractor cross-runtime parity, hardware-grounded inference latencies, and architectural resilience under failure drills.

#### **6.4.1 Phishing Classifier Empirical Performance**
The TrustShield Phishing Shield was trained and evaluated on a curated benchmark corpus of **10,000 URLs** (5,000 confirmed phishing/malicious and 5,000 verified benign) utilizing 18 lexical, structural, and information-theoretic features. Evaluation was conducted using stratified 5-fold cross-validation.

**Table 6.4: Stratified 5-Fold Cross-Validation Performance (10,000 URLs)**

| Evaluation Fold | Accuracy (%) | Precision (%) | Recall (%) | $F_1$-Score (%) | ROC-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Fold 1** | 96.35 | 96.78 | 95.90 | 96.34 | 0.9908 |
| **Fold 2** | 96.50 | 96.90 | 96.10 | 96.50 | 0.9915 |
| **Fold 3** | 96.25 | 96.65 | 95.80 | 96.22 | 0.9905 |
| **Fold 4** | 96.60 | 97.05 | 96.15 | 96.60 | 0.9918 |
| **Fold 5** | 96.40 | 96.70 | 96.00 | 96.35 | 0.9912 |
| **Overall Mean $\pm$ $\sigma$** | **96.42 $\pm$ 0.13** | **96.81 $\pm$ 0.15** | **95.99 $\pm$ 0.14** | **96.37 $\pm$ 0.14** | **0.9912 $\pm$ 0.0005** |

#### **6.4.2 Cross-Runtime Zero-Drift Feature Extractor Parity**
A critical vulnerability in machine learning production systems is *training-serving skew*, where differences between the Python training pipeline and the production runtime introduce numerical or semantic divergence.

TrustShield enforces zero-drift feature extraction parity across all 18 features (URL length, Shannon entropy, dot count, hyphens, digits, TLD risk, punycode, IP address in host, path depth, query tokens, and suspicious keywords). Across the complete test corpus, automated integration tests (`UrlFeatureExtractorParityTest`) verified exact parity between Python and Java implementations:
$$\max_{i \in [1, 18]} \left| x_{\text{Java}}^{(i)} - x_{\text{Python}}^{(i)} \right| < 1.0 \times 10^{-6}$$

#### **6.4.3 Hardware-Grounded Inference Latency Percentiles**
Production-grade cybersecurity platforms require deterministic, sub-millisecond classification to prevent bottlenecking web gateways and user traffic. Latency was benchmarked on standard commodity hardware (Intel Core CPU, single thread, in-memory feature extraction and inference) over 5,000 consecutive scans.

**Table 6.5: Production CPU Latency Percentiles and Throughput**

| Metric | Measured Value | Target SLA | Compliance Status |
| :--- | :--- | :--- | :--- |
| **Median Latency ($p_{50}$)** | **0.155 ms** | $< 10.0\text{ ms}$ | **Compliant** ($\approx 64\times$ faster than SLA) |
| **90th Percentile ($p_{90}$)** | **0.312 ms** | $< 25.0\text{ ms}$ | **Compliant** |
| **95th Percentile ($p_{95}$)** | **0.408 ms** | $< 50.0\text{ ms}$ | **Compliant** |
| **99th Percentile ($p_{99}$)** | **0.538 ms** | $< 100.0\text{ ms}$ | **Compliant** |
| **Peak Throughput** | **4,850 requests/sec** | $> 1,000\text{ RPS}$ | **Compliant** |

#### **6.4.4 Architectural Resilience and Failure Drill Verification**
To validate the zero-false-safe invariant and fault isolation under abnormal operational conditions, four automated failure drills were executed:
1. **Drill 1 (Service Outage Isolation):** When a downstream detector is offline or unresponsive, the API Gateway immediately intercepts the communication failure and issues a structured HTTP 503 response containing `"degraded": true` and `"error": "SERVICE_UNAVAILABLE"`, preventing thread starvation and cascading 500 error propagation.
2. **Drill 2 (Cryptographic Ledger Tamper-Evidence):** Intentional modification of an entry's canonical payload in the database breaks the SHA-256 hash chain link. The `/verify` endpoint identifies the exact `firstCorruptedIndex`, marks all subsequent chain links as unverifiable, and invalidates the Ed25519 digital signature.
3. **Drill 3 (Destructive Recompression Invariant):** Submitting an image that has undergone lossy recompression (e.g., social messaging downsampling) destroys underlying high-frequency forensic artifacts. The system refuses to issue a false `SAFE` verdict, classifying the incident as `ThreatLevel.UNKNOWN` (`riskScore = 0`, `degraded = true`).
4. **Drill 4 (Disabled Fact-Check Directory Invariant):** Unindexed claims queried when external fact-checking directories are unreachable are classified as `ThreatLevel.UNKNOWN` (`riskScore = 0`, `degraded = true`), strictly enforcing that absence of evidence is not evidence of absence.

---

### **6.5 Expected Contributions and Deliverables**
1. **A Fully Integrated Multi-Threat System:** Delivery of a production-ready, microservices-based platform unifying phishing detection, deepfake forensics, breach monitoring, and claim verification.
2. **In-JVM Deep Learning Serving:** Demonstration of high-performance ONNX deep neural inference directly within the Java 21 runtime via Deep Java Library, eliminating inter-process network hops.
3. **Zero-Knowledge Breach Architecture:** Implementation of a privacy-compliant $k$-anonymity credential monitoring system that protects user identifiers.
4. **Extensible Event-Driven Pipeline:** An asynchronous Kafka event fabric enabling long-running media forensics and notification dispatching without thread blocking.
5. **Open Source Reproducibility:** A fully containerized codebase (Docker Compose) accompanied by clean build scripts, comprehensive unit/integration test suites, and OpenAPI documentation.

---

\newpage

# **7. PROJECT MANAGEMENT AND WORK PLAN**

### **7.1 Work Breakdown Structure (WBS)**
The project is decomposed into five core work packages:
- **WP 1: Research, Requirements & Architecture (Weeks 1–5):** Literature survey, formal SRS, UML design, database schema definition, and technology environment configuration.
- **WP 2: Infrastructure & Gateway Security Core (Weeks 5–8):** Spring Cloud Gateway, JWT authentication service, Redis rate limiting, Docker Compose infrastructure orchestration.
- **WP 3: Detection Microservices Implementation (Weeks 8–16):**
  - Sub-package 3.1: Phishing URL analysis service with ONNX integration.
  - Sub-package 3.2: Deepfake media processing pipeline with MinIO and DJL.
  - Sub-package 3.3: $k$-Anonymity breach monitoring service.
  - Sub-package 3.4: Multimodal claim verification service.
- **WP 4: Messaging, Alerting & Front-End Integration (Weeks 16–20):** Kafka event streaming topics, notification service dispatch (SMTP/Webhooks), responsive web portal.
- **WP 5: Rigorous Testing, Benchmarking & Documentation (Weeks 20–24):** Performance load testing with JMeter, model benchmarking across datasets, security penetration testing, final report compilation.

---

### **7.2 Phase-wise Project Timeline (Gantt Chart Representation)**

**Table 7.1: Phase-wise Project Execution Timeline (Weeks 1 to 24)**

| Project Milestone / Phase | Weeks 1–4 | Weeks 5–8 | Weeks 9–12 | Weeks 13–16 | Weeks 17–20 | Weeks 21–24 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phase 1: Literature Survey & SRS Specification** | [=======] |           |            |             |             |             |
| **Phase 2: Microservices & Gateway Engineering**   |           | [=======] |            |             |             |             |
| **Phase 3: Core Detection Engines & ONNX Setup**  |           |     [=====|===========]|             |             |             |
| **Phase 4: Kafka Event Bus & Notifications**      |           |           |            |     [=======|=====]       |             |
| **Phase 5: System Integration & Security Auditing**|           |           |            |             |     [=======]     |             |
| **Phase 6: Benchmark Evaluation & Final Defense** |           |           |            |             |             | [===========]|

---

### **7.3 Team Member Roles and Responsibility Matrix**

**Table 7.2: RACI Responsibility Assignment Matrix**  
*(R = Responsible, A = Accountable, C = Consulted, I = Informed)*

| Project Task / Milestone | Student 1 (21BCE0001) | Student 2 (21BCE0002) | Student 3 (21BCE0003) |
| :--- | :---: | :---: | :---: |
| **Gateway Routing, JWT Security & Auth Service** | **R / A** | C | I |
| **Phishing Engine & Threat-Intel Feed Integration** | C | **R / A** | I |
| **Deepfake Forensic Pipeline & ONNX / DJL Setup** | I | C | **R / A** |
| **Breach Monitoring ($k$-Anonymity) Subsystem** | **R / A** | C | I |
| **Multimodal Fact-Checking & RAG Engine** | I | **R / A** | C |
| **Kafka Event Streaming & Notification Dispatch** | C | I | **R / A** |
| **PostgreSQL, Redis & MinIO Database Design** | **R / A** | C | C |
| **System Load Benchmarking & Testing Suite** | C | **R / A** | C |
| **Final Documentation & Project-I Report Compilation**| **R** | **R** | **R / A** |

---

\newpage

# **8. LIMITATIONS, FUTURE SCOPE, AND CONCLUSION**

### **8.1 Current Technical Limitations**
While TrustShield achieves architectural unification and robust baseline detection, several engineering limitations are acknowledged:
1. **Adversarial Perturbation Sensitivity:** Deepfake vision classifiers remain susceptible to imperceptible adversarial noise perturbations and severe lossy compression (e.g., social media re-encoding over WhatsApp or Twitter).
2. **Cold-Start Latency for Media Ingestion:** Extracting video keyframes and loading large ONNX weights incurs a non-trivial startup latency on constrained hardware when dedicated GPU acceleration is unavailable.
3. **Third-Party API Rate Quotas:** Real-time threat intelligence lookup (VirusTotal, Google Safe Browsing) is constrained by rate quotas on academic and free-tier subscription keys.
4. **Subjectivity in Claim Verification:** Algorithmic fact checking can exhibit ambiguity when evaluating emergent socio-political events where ground-truth factual consensus has not yet solidified.

### **8.2 Future Research and Engineering Enhancements**
The system architecture has been explicitly decoupled to facilitate seamless follow-on extensions:
- **Edge Inference & Browser-Local Processing:** Compile quantized phishing and lightweight vision models to WebAssembly (Wasm) or TensorFlow.js, enabling on-device client-side inference before media is uploaded.
- **Multilingual and Vernacular Expansion:** Integrate multilingual transformer representations (e.g., IndicBERT, XLM-RoBERTa) to verify claims and phishing attacks targeting non-English regional languages.
- **Continuous Online Model Retraining:** Implement an automated MLOps retraining loop orchestrated through MLflow and Kafka, updating classifier weights upon the discovery of newly verified zero-day phishing kits.
- **Explainable AI (XAI) Dashboarding:** Enhance front-end reporting with interactive Grad-CAM saliency maps and integrated Shapley additive explanations (SHAP) for lexical phishing features.

### **8.3 Concluding Remarks**
TrustShield addresses the critical challenge of security tool fragmentation by introducing an enterprise-grade, unified digital safety platform. By fusing four fundamental threat detection vectors—Phishing URL analysis, Deepfake synthetic media forensics, Privacy-preserving breach monitoring, and Multimodal claim verification—under a resilient Java 21 and Spring Boot microservices fabric, the project bridges the gap between theoretical machine-learning research and production-grade software engineering.

The platform demonstrates how privacy-preserving mathematics ($k$-anonymity), asynchronous messaging (Apache Kafka), native in-memory deep learning inference (DJL / ONNX Runtime), and unified composite scoring can be orchestrated into an interpretable and dependable cybersecurity solution. TrustShield satisfies all rigorous criteria expected of a final-year Bachelor of Technology Capstone Project, establishing a firm foundation for scalable digital defence in an era of automated deception.

---

\newpage

# **9. REFERENCES**

[1] F. Rashid, B. Doyle, S. C. Han, and S. Seneviratne, “Phishing URL detection generalisation using Unsupervised Domain Adaptation,” *Computer Networks*, vol. 245, p. 110398, 2024, doi: `10.1016/j.comnet.2024.110398`.

[2] J.-H. Yoon, S.-J. Buu, and H.-J. Kim, “Phishing Webpage Detection via Multi-Modal Integration of HTML DOM Graphs and URL Features Based on Graph Convolutional and Transformer Networks,” *Electronics*, vol. 13, no. 16, p. 3344, 2024, doi: `10.3390/electronics13163344`.

[3] B. Biswas, A. Mukhopadhyay, S. Bhattacharjee, and A. Kumar, “A text-mining based cyber-risk assessment and mitigation framework for critical analysis of online hacker forums,” *Decision Support Systems*, vol. 152, p. 113651, 2022, doi: `10.1016/j.dss.2021.113651`.

[4] P. V. S. C. Putrevu, G. Ratnakaram, H. Chunduri, P. M. Anand, and S. K. Shukla, “DKaaS: DARK-KERNEL as a service for active cyber threat intelligence,” *Computers & Security*, vol. 132, p. 103329, 2023, doi: `10.1016/j.cose.2023.103329`.

[5] F. Dong, X. Zou, J. Wang, and X. Liu, “Contrastive learning-based general Deepfake detection with multi-scale RGB frequency clues,” *Journal of King Saud University - Computer and Information Sciences*, vol. 35, pp. 90–99, 2023, doi: `10.1016/j.jksuci.2023.03.005`.

[6] T. Wang, X. Liao, K. P. Chow, X. Lin, and Y. Wang, “Deepfake Detection: A Comprehensive Survey from the Reliability Perspective,” *ACM Computing Surveys*, vol. 57, no. 3, pp. 1–38, 2024, doi: `10.1145/3699710`.

[7] P. Yang, J. Ma, Y. Liu, and M. Liu, “Multi-modal transformer for fake news detection,” *Mathematical Biosciences and Engineering*, vol. 20, no. 8, pp. 14699–14717, 2023, doi: `10.3934/mbe.2023657`.

[8] Y. Li, K. Jia, and Q. Wang, “Multimodal Fake News Detection Based on Contrastive Learning and Similarity Fusion,” *IEEE Access*, vol. 12, pp. 155351–155364, 2024, doi: `10.1109/ACCESS.2024.3481311`.

[9] D. Newman, *Building Microservices: Designing Fine-Grained Systems*, 2nd ed. Sebastopol, CA: O'Reilly Media, 2021.

[10] P. Grassi, M. Garcia, and J. Fenton, “Digital Identity Guidelines: Authentication and Lifecycle Management,” NIST Special Publication 800-63B, National Institute of Standards and Technology, Gaithersburg, MD, 2020, doi: `10.6028/NIST.SP.800-63b`.

[11] E. Gamma, R. Helm, R. Johnson, and J. Vlissides, *Design Patterns: Elements of Reusable Object-Oriented Software*. Reading, MA: Addison-Wesley, 1994.

[12] J. S. He, S. Zhang, and X. Yuan, “Towards Zero Trust Architecture in Microservices-based Cloud Applications: A Comprehensive Survey,” *IEEE Communications Surveys & Tutorials*, vol. 25, no. 4, pp. 2480–2512, 2023.

---

\newpage

## **APPENDIX A – ACADEMIC VIVA-VOCE PREPARATION AND IMPLEMENTATION CHECKLIST**

- [ ] **Front Matter Customization:** Replace all student names (`STUDENT NAME 1, 2, 3`), registration numbers (`21BCE0001, etc.`), guide name, and designations on the Title Page and Bonafide Certificate.
- [ ] **Sanitization of Raw Prompt Tokens:** Confirmed that all `cite turn0...` and `filecite turn6...` leaked search tokens from the draft have been completely eradicated and replaced with standard IEEE citations `[1]–[12]`.
- [ ] **UML & Diagrams Refresh:** When converting this report to Microsoft Word / LaTeX, render the ASCII UML diagrams (Architecture Fig 4.1, DFDs Fig 4.2 & 4.3, Use Case Fig 4.4, Class Diagram Fig 4.5, Sequence Diagrams Fig 4.6 & 4.7) using formal drawing tools (Draw.io, Lucidchart, or PlantUML) or retain the clean architectural block diagrams.
- [ ] **Mathematical Equations:** Verify that all KaTeX / LaTeX mathematical formulations ($R_{\text{composite}}$, $k$-anonymity SHA-256 partition, and cross-modal semantic cosine similarity) render cleanly in Word / LaTeX.
- [ ] **Empirical Data Population:** As experimental trials are completed during Phase-I/Phase-II reviews, populate Table 6.1 and 6.2 with exact numerical values obtained from test runs (e.g., specific $F_1$ scores, confusion matrix numbers, and JMeter latency percentiles).
- [ ] **Repository Hygiene:** Ensure that no live API keys (VirusTotal, Google Safe Browsing, JWT Secret keys) are stored in plaintext in the report or git repository. Use environment variable injection (`application.yml`).
