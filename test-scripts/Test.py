import sys
import os
import argparse
import base64
from lxml import etree
from signxml import (
    XMLVerifier,
    SignatureConfiguration,
    InvalidSignature,
    InvalidDigest,
    InvalidCertificate,
)
from signxml.xades import XAdESVerifier
from cryptography import x509


def _extract_cert(root):
    """Extract the X.509 certificate from the KeyInfo element."""
    ns = {"ds": "http://www.w3.org/2000/09/xmldsig#"}
    cert_elem = root.find(".//ds:X509Certificate", ns)
    if cert_elem is None:
        return None
    cert_der = base64.b64decode(cert_elem.text.strip())
    return x509.load_der_x509_certificate(cert_der)


def verify_xml(xml_file: str):
    try:
        parser = etree.XMLParser(
            remove_blank_text=False,
            resolve_entities=False
        )
        root = etree.parse(xml_file, parser).getroot()
        cert = _extract_cert(root)

        # =========================
        # Verify XMLDSig
        # =========================
        config = SignatureConfiguration(
            require_x509=False,
            expect_references=False,
        )
        try:
            result = XMLVerifier().verify(
                root,
                x509_cert=cert,
                expect_config=config,
                validate_schema=False,
            )

            print(result)

            print("✓ XMLDSig hợp lệ")

        except InvalidDigest as e:
            print("✗ DigestValue không khớp.")
            print("  -> Reference hoặc dữ liệu được ký đã bị thay đổi.")
            print(e)
            return False

        except InvalidSignature as e:
            print("✗ SignatureValue không hợp lệ.")
            print("  -> Sai khóa công khai hoặc SignedInfo đã bị thay đổi.")
            print(e)
            return False

        except InvalidCertificate as e:
            print("✗ Certificate trong KeyInfo không hợp lệ.")
            print(e)
            return False

        # =========================
        # Verify XAdES nếu có
        # =========================
        xades = root.xpath(
            "//*[local-name()='QualifyingProperties']"
        )

        if xades:
            try:
                XAdESVerifier().verify(
                    root,
                    x509_cert=cert,
                    expect_config=config,
                    validate_schema=False,
                )
                print("✓ XAdES hợp lệ")

            except InvalidDigest as e:
                print("✗ SignedProperties DigestValue không khớp.")
                print(e)
                return False

            except InvalidSignature as e:
                print("✗ XAdES verification thất bại.")
                print(e)
                return False
        else:
            print("Không có XAdES.")

        print("✓ Verify thành công")
        return True

    except etree.XMLSyntaxError as e:
        print("✗ XML không hợp lệ")
        print(e)
        return False

    except Exception as e:
        print(f"✗ {type(e).__name__}: {e}")
        return False


if __name__ == "__main__":

    parser = argparse.ArgumentParser(

        description="Verify XMLDSig/XAdES signature"

    )

    parser.add_argument(

        "xml_file",

        help="Path to the signed XML file"

    )

    args = parser.parse_args()

    if not os.path.isfile(args.xml_file):

        print(f"✗ File not found: {args.xml_file}")

        sys.exit(1)

    success = verify_xml(args.xml_file)

    sys.exit(0 if success else 1)