# XML-Kit Signature Placement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the initial XML-Kit Java library with a placement-aware remote-signing flow that supports enveloped, enveloping, and detached XML signature assembly.

**Architecture:** Convert the generated Gradle application into a Java library, then implement a small XMLDSig/XAdES-oriented domain model centered on `XmlSignatureBuilder`, `SigningRequest`, and a strict `PlacementResolver`. Keep signing two-phase: `.prepare()` computes digests and captures the resolved insertion target, while `.complete(...)` assembles the final XML and optionally adds XAdES unsigned properties for timestamp-bearing profiles.

**Tech Stack:** Java 21, Gradle, JUnit Jupiter, JDK DOM/XPath/XML crypto primitives.

---

### Task 1: Bootstrap the library project

**Files:**
- Create: `build.gradle`
- Create: `settings.gradle`
- Create: `gradle/libs.versions.toml`
- Create: `src/main/java/com/truongnq/xmlkit/api/XmlSignatureBuilder.java`
- Create: `src/test/java/com/truongnq/xmlkit/api/XmlSignatureBuilderBootstrapTest.java`

- [ ] **Step 1: Write the failing build-layout test**

```java
package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;

class XmlSignatureBuilderBootstrapTest {
    @Test
    void builderClassExists() {
        assertDoesNotThrow(() -> Class.forName("com.truongnq.xmlkit.api.XmlSignatureBuilder"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests com.truongnq.xmlkit.api.XmlSignatureBuilderBootstrapTest`
Expected: FAIL because the Java sources and library build are not created yet.

- [ ] **Step 3: Replace the generated application build with a library build**

```groovy
plugins {
    id 'java-library'
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation libs.junit.jupiter
    testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }

    withSourcesJar()
    withJavadocJar()
}

tasks.named('test') {
    useJUnitPlatform()
}
```

- [ ] **Step 4: Add the bootstrap builder class**

```java
package com.truongnq.xmlkit.api;

public final class XmlSignatureBuilder {
    private XmlSignatureBuilder() {
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./gradlew test --tests com.truongnq.xmlkit.api.XmlSignatureBuilderBootstrapTest`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add build.gradle settings.gradle gradle/libs.versions.toml src/main/java/com/truongnq/xmlkit/api/XmlSignatureBuilder.java src/test/java/com/truongnq/xmlkit/api/XmlSignatureBuilderBootstrapTest.java
git commit -m "build: convert xml-kit to library project"
```

### Task 2: Add domain types and placement resolution

**Files:**
- Create: `src/main/java/com/truongnq/xmlkit/api/XmlSignatureBuilder.java`
- Create: `src/main/java/com/truongnq/xmlkit/exception/XmlKitException.java`
- Create: `src/main/java/com/truongnq/xmlkit/exception/PlacementResolutionException.java`
- Create: `src/main/java/com/truongnq/xmlkit/model/CanonicalizationMethod.java`
- Create: `src/main/java/com/truongnq/xmlkit/model/DigestAlgorithm.java`
- Create: `src/main/java/com/truongnq/xmlkit/model/SignatureProfile.java`
- Create: `src/main/java/com/truongnq/xmlkit/model/SignatureType.java`
- Create: `src/main/java/com/truongnq/xmlkit/core/PlacementResolver.java`
- Test: `src/test/java/com/truongnq/xmlkit/core/PlacementResolverTest.java`

- [ ] **Step 1: Write the failing placement tests**

```java
@Test
void resolvesExactlyOneNode() {
    Document document = TestXml.document("<root xmlns='urn:test'><slot/></root>");

    Node node = new PlacementResolver().resolve(document, "//*[local-name()='slot']", Map.of());

    assertEquals("slot", node.getLocalName());
}

@Test
void failsWhenXPathMatchesNothing() {
    Document document = TestXml.document("<root><slot/></root>");

    assertThrows(PlacementResolutionException.class, () ->
        new PlacementResolver().resolve(document, "//missing", Map.of()));
}

@Test
void failsWhenXPathMatchesMultipleNodes() {
    Document document = TestXml.document("<root><slot/><slot/></root>");

    assertThrows(PlacementResolutionException.class, () ->
        new PlacementResolver().resolve(document, "//slot", Map.of()));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests com.truongnq.xmlkit.core.PlacementResolverTest`
Expected: FAIL because `PlacementResolver` and supporting types do not exist.

- [ ] **Step 3: Implement the minimal model and placement resolver**

```java
public final class PlacementResolver {
    public Node resolve(Document document, String expression, Map<String, String> namespaces) {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(new MapNamespaceContext(namespaces));
        NodeList nodes = (NodeList) xpath.evaluate(expression, document, XPathConstants.NODESET);
        if (nodes.getLength() != 1) {
            throw new PlacementResolutionException(expression, nodes.getLength());
        }
        return nodes.item(0);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew test --tests com.truongnq.xmlkit.core.PlacementResolverTest`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/truongnq/xmlkit/api/XmlSignatureBuilder.java src/main/java/com/truongnq/xmlkit/exception/XmlKitException.java src/main/java/com/truongnq/xmlkit/exception/PlacementResolutionException.java src/main/java/com/truongnq/xmlkit/model src/main/java/com/truongnq/xmlkit/core/PlacementResolver.java src/test/java/com/truongnq/xmlkit/core/PlacementResolverTest.java
git commit -m "feat: add placement resolution primitives"
```

### Task 3: Implement the two-phase signing API

**Files:**
- Create: `src/main/java/com/truongnq/xmlkit/api/SigningRequest.java`
- Create: `src/main/java/com/truongnq/xmlkit/api/ExtendedSigningRequest.java`
- Create: `src/main/java/com/truongnq/xmlkit/api/SignedDocument.java`
- Create: `src/main/java/com/truongnq/xmlkit/core/DigestEngine.java`
- Create: `src/main/java/com/truongnq/xmlkit/core/SignedInfoBuilder.java`
- Create: `src/main/java/com/truongnq/xmlkit/exception/CanonicalizationException.java`
- Create: `src/main/java/com/truongnq/xmlkit/exception/SignatureAssemblyException.java`
- Test: `src/test/java/com/truongnq/xmlkit/api/XmlSignatureBuilderPrepareTest.java`

- [ ] **Step 1: Write the failing prepare/complete tests**

```java
@Test
void prepareReturnsDigestAndCompleteInsertsEnvelopedSignature() {
    Document document = TestXml.document("<invoice><slot/></invoice>");

    SigningRequest request = XmlSignatureBuilder.forDocument(document)
        .signatureType(SignatureType.ENVELOPED)
        .profile(SignatureProfile.XMLDSIG)
        .placementXPath("//slot")
        .prepare();

    assertFalse(request.getDigestToSign().isEmpty());

    SignedDocument signed = request.complete(new byte[] {1, 2, 3});

    assertTrue(signed.xml().contains("<Signature"));
    assertTrue(signed.xml().contains("<SignatureValue"));
}

@Test
void xadesTPrepareReturnsExtendedRequest() {
    Document document = TestXml.document("<invoice><slot/></invoice>");

    SigningRequest request = XmlSignatureBuilder.forDocument(document)
        .signatureType(SignatureType.ENVELOPED)
        .profile(SignatureProfile.XADES_T)
        .placementXPath("//slot")
        .prepare();

    assertInstanceOf(ExtendedSigningRequest.class, request);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests com.truongnq.xmlkit.api.XmlSignatureBuilderPrepareTest`
Expected: FAIL because the signing request API and builder implementation do not exist.

- [ ] **Step 3: Implement the minimal signing flow**

```java
public SigningRequest prepare() {
    Node placementTarget = placementResolver.resolve(document, placementXPath, placementNamespaces);
    byte[] signedInfoBytes = signedInfoBuilder.build(document, signatureType, profile);
    byte[] digest = digestEngine.digest(digestAlgorithm, signedInfoBytes);
    PreparedSignature prepared = new PreparedSignature(document, placementTarget, signatureType, profile, signedInfoBytes);
    return profile.requiresTimestamp()
        ? new ExtendedSigningRequest(prepared, digestEngine, digest)
        : new SigningRequest(prepared, digest);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew test --tests com.truongnq.xmlkit.api.XmlSignatureBuilderPrepareTest`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/truongnq/xmlkit/api src/main/java/com/truongnq/xmlkit/core/DigestEngine.java src/main/java/com/truongnq/xmlkit/core/SignedInfoBuilder.java src/main/java/com/truongnq/xmlkit/exception/CanonicalizationException.java src/main/java/com/truongnq/xmlkit/exception/SignatureAssemblyException.java src/test/java/com/truongnq/xmlkit/api/XmlSignatureBuilderPrepareTest.java
git commit -m "feat: add remote signing prepare flow"
```

### Task 4: Support placement-aware assembly for all signature types

**Files:**
- Modify: `src/main/java/com/truongnq/xmlkit/api/SigningRequest.java`
- Modify: `src/main/java/com/truongnq/xmlkit/api/ExtendedSigningRequest.java`
- Create: `src/main/java/com/truongnq/xmlkit/core/SignatureAssembler.java`
- Create: `src/test/java/com/truongnq/xmlkit/api/SignaturePlacementIntegrationTest.java`

- [ ] **Step 1: Write the failing integration tests**

```java
@Test
void envelopedPlacementUsesResolvedTargetNode() {
    SignedDocument signed = sign(
        SignatureType.ENVELOPED,
        "<root><before/><slot/><after/></root>",
        "//slot");

    assertTrue(TestXml.childNames(signed.document(), "/root/slot").contains("Signature"));
}

@Test
void envelopingPlacementAttachesEnvelopeToTargetNode() {
    SignedDocument signed = sign(
        SignatureType.ENVELOPING,
        "<root><container/></root>",
        "//container");

    assertTrue(TestXml.childNames(signed.document(), "/root/container").contains("Signature"));
}

@Test
void detachedPlacementAttachesDetachedSignatureArtifactToTargetNode() {
    SignedDocument signed = sign(
        SignatureType.DETACHED,
        "<root><container/></root>",
        "//container");

    assertTrue(TestXml.childNames(signed.document(), "/root/container").contains("Signature"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests com.truongnq.xmlkit.api.SignaturePlacementIntegrationTest`
Expected: FAIL because assembly is not placement-aware for all signature types.

- [ ] **Step 3: Implement placement-aware assembly**

```java
switch (prepared.signatureType()) {
    case ENVELOPED -> appendSignatureElement(target, signatureElement);
    case ENVELOPING -> appendEnvelopingSignature(target, signatureElement, prepared.originalDocument());
    case DETACHED -> appendDetachedSignature(target, signatureElement, prepared.referenceUri());
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew test --tests com.truongnq.xmlkit.api.SignaturePlacementIntegrationTest`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/truongnq/xmlkit/api/SigningRequest.java src/main/java/com/truongnq/xmlkit/api/ExtendedSigningRequest.java src/main/java/com/truongnq/xmlkit/core/SignatureAssembler.java src/test/java/com/truongnq/xmlkit/api/SignaturePlacementIntegrationTest.java
git commit -m "feat: support placement-aware signature assembly"
```

### Task 5: Add minimal XAdES extensions and full regression coverage

**Files:**
- Modify: `src/main/java/com/truongnq/xmlkit/api/ExtendedSigningRequest.java`
- Modify: `src/main/java/com/truongnq/xmlkit/core/SignatureAssembler.java`
- Create: `src/test/java/com/truongnq/xmlkit/api/XadesSigningFlowTest.java`
- Create: `src/test/java/com/truongnq/xmlkit/testing/TestXml.java`

- [ ] **Step 1: Write the failing XAdES tests**

```java
@Test
void extendedRequestExposesSignatureValueDigest() {
    ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
            TestXml.document("<root><slot/></root>"))
        .signatureType(SignatureType.ENVELOPED)
        .profile(SignatureProfile.XADES_T)
        .placementXPath("//slot")
        .prepare();

    SignedDocument signed = request.complete(new byte[] {9, 8, 7}, new byte[] {7, 8, 9});

    assertTrue(signed.xml().contains("UnsignedProperties"));
    assertTrue(signed.xml().contains("EncapsulatedTimeStamp"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests com.truongnq.xmlkit.api.XadesSigningFlowTest`
Expected: FAIL because timestamp-capable completion is not implemented.

- [ ] **Step 3: Implement the minimal XAdES unsigned-properties flow**

```java
public SignedDocument complete(byte[] signatureValue, byte[] timestampToken) {
    byte[] signatureDigest = digestEngine.digest(DigestAlgorithm.SHA256, signatureValue);
    return assembler.assembleExtended(prepared, signatureValue, signatureDigest, timestampToken);
}
```

- [ ] **Step 4: Run the full test suite**

Run: `./gradlew test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/truongnq/xmlkit/api/ExtendedSigningRequest.java src/main/java/com/truongnq/xmlkit/core/SignatureAssembler.java src/test/java/com/truongnq/xmlkit/api/XadesSigningFlowTest.java src/test/java/com/truongnq/xmlkit/testing/TestXml.java
git commit -m "feat: add minimal xades timestamp flow"
```
