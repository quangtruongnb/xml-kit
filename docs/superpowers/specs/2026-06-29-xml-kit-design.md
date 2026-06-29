# XML-Kit Design Specification

## Overview
XML-Kit is a Java library designed to facilitate XML Digital Signatures (XMLDSig) and XAdES (XML Advanced Electronic Signatures). Its primary focus is supporting a **remote signing flow** (hash extraction), where the private key is held securely in a remote HSM or signing service. 

## Technical Constraints
* **Language:** Java 21
* **Build System:** Gradle
* **Package Name:** `com.truongnq.xmlkit`
* **Dependencies:** Uses JDK's built-in XML/crypto capabilities where possible.

## Features
* **Signature Types:** Enveloped, Enveloping, and Detached.
* **Profiles Supported:** 
    * XMLDSig
    * XAdES-BES (Basic Electronic Signature)
    * XAdES-T (Timestamp - external token provision)
    * XAdES-C (Complete - with validation data references)
    * XAdES-X-L (Extended Long-term - embedding full validation data)
* **Remote Flow Focus:** The library computes the digest to sign and allows the client to inject the signature value later.
* **External Timestamping:** For XAdES-T and beyond, the library computes the signature value digest, but the client is responsible for acquiring the timestamp token (RFC 3161) from a TSA and supplying it back to the library to complete the XAdES-T structure.
* **Signature Placement Control:** The caller can define where the generated signature artifact is placed by supplying a placement XPath expression plus namespace bindings. Placement applies to enveloped, enveloping, and detached outputs.

## Placement Model
Placement is resolved through the top-level `XmlSignatureBuilder`, not through profile-specific builders.

* **Target Expression:** The caller supplies a raw XPath expression that identifies the placement target.
* **Namespace Bindings:** The caller supplies a namespace prefix map used only for placement XPath evaluation.
* **Strict Resolution:** Placement must resolve to exactly one node. Zero matches or multiple matches fail preparation with a placement resolution error.
* **Stable Targeting:** Placement is resolved during `.prepare()`, and the resolved insertion point is retained for completion so the final assembly step does not reinterpret XPath against a changed document.

Placement semantics vary by signature type:

* **Enveloped:** The XPath target identifies the node where the `<Signature>` element is inserted into the existing document.
* **Enveloping:** The XPath target identifies the container node where the generated signature envelope is attached in the output document model.
* **Detached:** The XPath target identifies the node where the detached signature artifact or descriptor is emitted when the output is XML-based.

## Architecture

The system is composed of three main layers:
1. **Core Layer:** Handles XML Canonicalization (C14N), digest computation, placement target resolution, and building the `<SignedInfo>` element.
2. **Profile Layer:** Specialized builders for XMLDSig and various XAdES forms, managing the intricate XML structures (`<QualifyingProperties>`, `<SignedProperties>`, `<UnsignedProperties>`).
3. **API Layer:** A fluent `XmlSignatureBuilder` that orchestrates the flow, including placement configuration and validation.

### Public Builder Contract

The builder remains the main integration point for clients. In addition to document, profile, certificate, and algorithm configuration, it must expose placement configuration with:

* A placement XPath expression.
* A namespace prefix map for placement evaluation.
* Validation that placement is configured consistently with the chosen signature type and fails fast when resolution is ambiguous.

### Remote Signing Workflow

The API is designed for a two-phase signing process:

**Phase 1: Preparation**
1. Client configures the `XmlSignatureBuilder` with the document, signature type, algorithms, certificate, profile, placement XPath, and placement namespace bindings.
2. Client calls `.prepare()`.
3. The library resolves the placement target, validates that exactly one node matches, canonicalizes the necessary parts, constructs the `<SignedInfo>`, and computes the digest that needs to be signed.
4. The library returns a `SigningRequest` object that retains the resolved placement target for final assembly.

**Phase 2: Signing & Completion**
1. Client calls `signingRequest.getDigestToSign()`.
2. Client sends this digest to the remote HSM/service for signing.
3. Client receives the signature value bytes.
4. Client calls `signingRequest.complete(signatureValue)`.
    * *For XAdES-T/C/X-L:* The library will then expose the signature digest, client fetches timestamp, and calls another completion method on the extended request.
5. The library assembles the final XML using the placement target resolved during preparation and returns a `SignedDocument`.

## Package Structure

```
com.truongnq.xmlkit
├── api
│   ├── XmlSignatureBuilder        # Fluent entry point
│   ├── SigningRequest             # Base request for hash extraction
│   ├── ExtendedSigningRequest     # Request for XAdES-T+ needing timestamps
│   └── SignedDocument             # Wrapper for the final XML result
├── model
│   ├── SignatureType              # ENVELOPED, ENVELOPING, DETACHED
│   ├── DigestAlgorithm            # SHA256, SHA384, SHA512
│   ├── CanonicalizationMethod     # C14N_EXCLUSIVE, C14N_INCLUSIVE
│   └── SignatureProfile           # XMLDSIG, XADES_BES, XADES_T, XADES_C, XADES_X_L
├── core
│   ├── CanonicalizationEngine     # XML C14N implementation
│   ├── DigestEngine               # Hash computations
│   ├── PlacementResolver          # Resolves placement XPath to a single target node
│   ├── ReferenceBuilder           # Builds <Reference> elements
│   └── SignedInfoBuilder          # Builds <SignedInfo>
├── profile
│   ├── XmlDsigProfileBuilder      # Vanilla XMLDSig
│   └── xades
│       ├── XAdESBESBuilder        # Constructs BES properties
│       ├── XAdESTBuilder          # Constructs T properties (UnsignedProperties)
│       └── XAdESLongBuilder       # Constructs C / X-L properties
└── exception
    ├── XmlKitException
    ├── CanonicalizationException
    ├── PlacementResolutionException
    └── SignatureAssemblyException
```

## Self-Review / Scoping
* **Scope:** Well bounded to signature assembly and digest calculation. No key management is required locally.
* **Ambiguity:** XAdES timestamping requires two trips to remote services (one for signing, one for TSA). The API accommodates this by having an `ExtendedSigningRequest` for XAdES-T+ which asks for the timestamp token after the signature value is provided.
* **Placement Rule:** Signature placement is builder-configured, XPath-based, and strict. The library never falls back to implicit first-match or best-effort insertion behavior.
