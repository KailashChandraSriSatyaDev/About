# NLP-Based GRC Compliance Mapping and Drift Detection

## Overview

This research project explores NLP-based automation to map organizational security policies to ISO/IEC 27001:2022 control requirements and highlight potential semantic misalignment as policies, implementations, or requirements change.

## Problem

Manual policy-to-control mapping can be time-consuming and may be inconsistent across reviewers. The research investigates semantic text representations as a way to support candidate matching and help reviewers prioritize items that need human assessment.

## Approach

- Used Sentence-BERT embeddings and cosine similarity to compare policy text with control requirements.
- Explored policy-to-control mapping and continuous monitoring concepts.
- Proposed a Drift Index (DI) to quantify semantic divergence over time.
- Framed automated matches as decision support, not as a replacement for compliance-owner judgment.

## Research Evaluation

The broader research compared TF-IDF, BM25, SecureBERT, and SBERT approaches across a dataset of 206 policies and 93 compliance artefacts from three public sources.

For the fine-tuned versus zero-shot SBERT comparison, the reported results were:

- Exact-match accuracy: 28.8% to 39.9%.
- Top-3 accuracy: 51.0% to 65.1%.
- Paired-test p-value: 0.0145.
- Recalibrated out-of-fold ROC AUC: 0.575 to 0.667.
- Inter-rater agreement: Cohen's kappa of 0.58.

These metrics belong to the research evaluation and should be interpreted with their dataset, labelling process, and validation setup in mind. Automated similarity is a prioritization signal, not proof that a control is compliant.

## Potential Applications

- Policy and control gap analysis.
- Periodic policy review and standards migration.
- Human review queues based on confidence or risk.
- Monitoring semantic drift between policy language and control requirements.

## Relevance to AI Security

The project demonstrates an approach to translating a security/compliance problem into an NLP pipeline, evaluating retrieval/matching quality, and communicating the limitations of automated decisions. Similar disciplines are useful when evaluating AI-enabled security tooling: validate the signal, calibrate confidence, retain an audit trail, and keep people involved in consequential decisions.

## Related Research

The NLP-based GRC research was accepted at ICIMIA 2026.

## Scope Note

This page summarizes the research. This repository does not include the research dataset or claim to reproduce the published/accepted evaluation.
