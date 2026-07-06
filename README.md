# xml-kit

A lightweight, zero-dependency Java library for building XML Digital Signatures (XMLDSig) with first-class support for **remote/HSM signing workflows**. Built on top of the JDK's built-in XML APIs (`org.w3c.dom`, `javax.xml`), xml-kit separates digest computation from the actual signing operation, making it ideal for environments where the private key lives on a remote HSM, a cloud KMS, or behind a signing service API.

## Features

- **Remote signing by design** — `prepare()` returns the digest to sign; you bring your own signer
- **All signature types** — Enveloped, Enveloping, and Detached
- **XAdES profiles** — XMLDSIG, XAdES-BES, XAdES-T, XAdES-C, XAdES-X-L
- **Multi-target** — Sign multiple elements in a single `<Signature>`
- **Signature Objects** — Embed custom `<ds:Object>` and `<ds:SignatureProperties>` elements
- **No runtime dependencies** — Pure JDK 21+, uses only `java.xml` and `java.security`

## Requirements

- **Java 21+**
- **Gradle 8.7+** (Wrapper included)

## Quick Start

### Add to your project

Clone and publish to your local Maven repository, or reference the project directly:

```bash
git clone https://github.com/quangtruongnb/xml-kit.git
cd xml-kit
./gradlew build
```

### Basic Signing Flow (XMLDSIG)

The core workflow follows a **prepare → sign → complete** pattern:

```java
import com.truongnq.xmlkit.api.*;
import com.truongnq.xmlkit.model.*;

// 1. Parse your XML document
Document doc = /* your DOM Document */;

// 2. Configure and prepare the signature
SigningRequest request = XmlSignatureBuilder.forDocument(doc)
        .signatureType(SignatureType.ENVELOPED)
        .profile(SignatureProfile.XMLDSIG)
        .certificate(yourX509Certificate)
        .placementSelector(Selector.builder("//SlotElement").build())
        .prepare();

// 3. Send the digest to your remote signer / HSM / KMS
byte[] digestToSign = request.getDigestToSign();
byte[] signatureValue = yourRemoteSigner.sign(digestToSign);

// 4. Complete the signature
SignedDocument signed = request.complete(signatureValue);

// 5. Get the result
String signedXml = signed.xml();       // Serialized XML string
Document signedDoc = signed.document(); // DOM Document
```

## Usage Guide

### Signature Types

#### Enveloped Signature

The `<Signature>` element is placed **inside** the document being signed:

```java
SigningRequest request = XmlSignatureBuilder.forDocument(doc)
        .signatureType(SignatureType.ENVELOPED)
        .certificate(certificate)
        .placementSelector(Selector.builder("//ContainerElement").build())
        .prepare();
```

#### Detached Signature

The `<Signature>` and the signed content are **siblings** within the same document:

```java
// Sign <Invoice> element, place signature at <SignatureSlot>
SigningRequest request = XmlSignatureBuilder.forDocument(doc)
        .signatureType(SignatureType.DETACHED)
        .certificate(certificate)
        .addTarget(Selector.builder("//Invoice").build())
        .placementSelector(Selector.builder("//SignatureSlot").build())
        .prepare();
```

#### Enveloping Signature

The signed content is **wrapped inside** the `<Signature>` as a `<ds:Object>`:

```java
SigningRequest request = XmlSignatureBuilder.forDocument(doc)
        .signatureType(SignatureType.ENVELOPING)
        .certificate(certificate)
        .placementSelector(Selector.builder("//Container").build())
        .prepare();
```

### Multi-Target Detached Signatures

Sign multiple elements in a single signature:

```java
SigningRequest request = XmlSignatureBuilder.forDocument(doc)
        .signatureType(SignatureType.DETACHED)
        .certificate(certificate)
        .addTarget(Selector.builder("//Invoice").build())
        .addTarget(Selector.builder("//Receipt").build())
        .placementSelector(Selector.builder("//SignatureSlot").build())
        .prepare();
```

Each target gets its own `<Reference>` in the `<SignedInfo>`. Elements without an `Id` attribute will have one auto-generated.

### XPath with Namespaces

Use `Selector` with namespace bindings for namespace-aware XPath resolution:

```java
Selector selector = Selector.builder("//inv:Invoice")
        .namespaces(Map.of("inv", "urn:example:invoice:v1"))
        .build();
```

### Reference Options

Customize how individual references are built:

```java
ReferenceOptions options = ReferenceOptions.builder()
        .referenceId("my-custom-id")
        .transforms(List.of(
            Transform.of("http://www.w3.org/2000/09/xmldsig#enveloped-signature"),
            Transform.of("http://www.w3.org/2001/10/xml-exc-c14n#")
        ))
        .build();

// Use with addTarget
builder.addTarget(selector, options);

// Or with targets list
builder.targets(List.of(TargetReference.of(selector, options)));
```

### Signature Profiles

#### XMLDSIG (default)

Standard XML Digital Signature:

```java
.profile(SignatureProfile.XMLDSIG)
```

#### XAdES-BES

Adds `<QualifyingProperties>` with `<SignedProperties>` (signing certificate reference, signing time):

```java
.profile(SignatureProfile.XADES_BES)
```

#### XAdES-T (with Timestamp)

Requires a timestamp token. The `prepare()` method returns an `ExtendedSigningRequest` with a **two-phase completion** flow:

```java
ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(doc)
        .signatureType(SignatureType.ENVELOPED)
        .profile(SignatureProfile.XADES_T)
        .certificate(certificate)
        .placementSelector(Selector.builder("//slot").build())
        .prepare();

// Phase 1: Sign the digest
byte[] signatureValue = remoteSigner.sign(request.getDigestToSign());
PostSignatureRequest postSignature = request.completeSignature(signatureValue);

// Phase 2: Timestamp the signature value
byte[] signatureValueDigest = postSignature.getSignatureValueDigest();
byte[] timestampToken = timestampAuthority.timestamp(signatureValueDigest);
SignedDocument signed = postSignature.completeTimestamp(timestampToken);
```

Or use the shorthand if you have both values:

```java
SignedDocument signed = request.complete(signatureValue, timestampToken);
```

### Signature Objects

Embed custom `<ds:Object>` elements inside the `<Signature>`.

#### Generic Object (arbitrary XML content)

```java
Element customData = doc.createElement("CustomData");
customData.setTextContent("evidence-content");

builder.addSignatureObject(SignatureObject.builder(customData)
        .id("evidence-obj")
        .includeInSignedInfo(true)  // adds a Reference in SignedInfo
        .build());
```

#### Signature Properties (`<ds:SignatureProperties>`)

```java
Element signingTime = doc.createElement("SigningTime");
signingTime.setTextContent("2026-07-02T21:00:00Z");

Element signerRole = doc.createElement("SignerRole");
signerRole.setTextContent("Approver");

builder
    .signatureId("sig-001")   // Target for SignatureProperty
    .addSignatureObject(SignatureObject.signatureProperties()
            .id("sig-props")
            .addProperty("prop-time", signingTime)
            .addProperty("prop-role", signerRole)
            .includeInSignedInfo(true)
            .build());
```

When a `SignatureProperty` object is added without an explicit `signatureId`, one is auto-generated so the `Target` attribute can reference the enclosing `<Signature>`.

#### Mixing Signed and Unsigned Objects

```java
builder
    .addSignatureObject(SignatureObject.builder(signedData)
            .id("signed-obj")
            .includeInSignedInfo(true)   // digest included in SignedInfo
            .build())
    .addSignatureObject(SignatureObject.builder(metadata)
            .includeInSignedInfo(false)  // decorative, not signed
            .build());
```

### Configuration Options

| Method | Default | Description |
|---|---|---|
| `signatureType(...)` | `DETACHED` | `ENVELOPED`, `ENVELOPING`, or `DETACHED` |
| `profile(...)` | `XMLDSIG` | `XMLDSIG`, `XADES_BES`, `XADES_T`, `XADES_C`, `XADES_X_L` |
| `prefix(...)` | `"ds"` | XML namespace prefix (e.g. `"ds"` → `<ds:Signature>`, `""` → `<Signature>`) |
| `digestAlgorithm(...)` | `SHA256` | `SHA256`, `SHA384`, `SHA512` |
| `canonicalizationMethod(...)` | `C14N_EXCLUSIVE` | `C14N_EXCLUSIVE` or `C14N_INCLUSIVE` |
| `certificate(...)` | *required* | X.509 certificate for `<KeyInfo>` |
| `placementSelector(...)` | *required* | XPath selector for where to place the `<Signature>` |
| `signatureId(...)` | auto if needed | Value for the `<Signature Id="...">` attribute |

## API Reference

### Core Classes

| Class | Description |
|---|---|
| `XmlSignatureBuilder` | Fluent builder — entry point for all signature operations |
| `SigningRequest` | Result of `prepare()` for XMLDSIG / XAdES-BES. Holds the digest and completes the signature |
| `ExtendedSigningRequest` | Result of `prepare()` for timestamp profiles (XAdES-T/C/X-L). Adds signature value → timestamp flow |
| `PostSignatureRequest` | Intermediate state after signing, before timestamping |
| `SignedDocument` | Final result containing the signed DOM `Document` and serialized XML `String` |
| `Selector` | XPath expression with optional namespace bindings |
| `TargetReference` | Pairs a `Selector` with optional `ReferenceOptions` for target elements |
| `ReferenceOptions` | Custom reference ID and transform URIs |
| `SignatureObject` | Custom `<ds:Object>` element (generic content or `<ds:SignatureProperties>`) |
| `SignatureProperty` | A single `<ds:SignatureProperty>` with optional ID and arbitrary content |
| `ValidationMaterial` | Additional certificates and revocation data for extended profiles |

### Model Enums

| Enum | Values |
|---|---|
| `SignatureType` | `ENVELOPED`, `ENVELOPING`, `DETACHED` |
| `SignatureProfile` | `XMLDSIG`, `XADES_BES`, `XADES_T`, `XADES_C`, `XADES_X_L` |
| `DigestAlgorithm` | `SHA256`, `SHA384`, `SHA512` |
| `CanonicalizationMethod` | `C14N_INCLUSIVE`, `C14N_EXCLUSIVE` |

## Building & Testing

```bash
# Build
./gradlew build

# Run tests
./gradlew test
```

## License

MIT
