//! ASN.1 extension extraction and XML parsing for SACI AuthnContext.
//!
//! Extracts the AuthnContext extension (OID 1.2.752.201.5.1) from an X.509
//! certificate, decodes the ASN.1 `AuthenticationContexts` SEQUENCE, and
//! parses the embedded XML into structured [`SAMLAuthContext`] objects.

use quick_xml::events::Event;
use quick_xml::Reader;
use x509_cert::Certificate;

use super::{
    AttributeMapping, AuthContextInfo, IdAttributes, MappingType, RawAuthenticationContext,
    SAMLAuthContext, SamlAttribute, AUTHN_CONTEXT_OID, SACI_CONTEXT_TYPE,
};
use crate::error::SaciError;

/// Extract and parse all SACI AuthnContext entries from a certificate.
///
/// Finds the extension with OID `1.2.752.201.5.1`, decodes the ASN.1
/// structure, and parses any SACI-typed context info XML into
/// [`SAMLAuthContext`] objects.
///
/// Returns an error if the extension is not found, or if parsing fails.
pub fn extract_authn_contexts(cert: &Certificate) -> Result<Vec<SAMLAuthContext>, SaciError> {
    let raw_contexts = extract_raw_contexts(cert)?;

    let mut results = Vec::new();
    for raw in &raw_contexts {
        if raw.context_type == SACI_CONTEXT_TYPE {
            if let Some(xml) = &raw.context_info {
                let parsed = parse_saml_auth_context(xml)?;
                results.push(parsed);
            }
        }
    }

    if results.is_empty() && raw_contexts.is_empty() {
        return Err(SaciError::ExtensionNotFound);
    }

    Ok(results)
}

/// Extract raw AuthenticationContext entries from the certificate's ASN.1 extension.
///
/// This performs only the ASN.1 decoding, not the XML parsing.
pub fn extract_raw_contexts(
    cert: &Certificate,
) -> Result<Vec<RawAuthenticationContext>, SaciError> {
    let authn_context_oid = const_oid::ObjectIdentifier::new_unwrap(AUTHN_CONTEXT_OID);

    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(SaciError::ExtensionNotFound)?;

    let ext = extensions
        .iter()
        .find(|e| e.extn_id == authn_context_oid)
        .ok_or(SaciError::ExtensionNotFound)?;

    let ext_bytes = ext.extn_value.as_bytes();
    decode_authentication_contexts(ext_bytes)
}

/// Decode ASN.1 `AuthenticationContexts` SEQUENCE.
///
/// ```text
/// AuthenticationContexts ::= SEQUENCE SIZE (1..MAX) OF AuthenticationContext
/// AuthenticationContext  ::= SEQUENCE {
///     contextType  UTF8String,
///     contextInfo  UTF8String OPTIONAL
/// }
/// ```
fn decode_authentication_contexts(
    der_bytes: &[u8],
) -> Result<Vec<RawAuthenticationContext>, SaciError> {
    let mut results = Vec::new();

    // Outer SEQUENCE
    let (tag, body) = parse_tlv(der_bytes)?;
    if tag != 0x30 {
        return Err(SaciError::Asn1(format!(
            "expected SEQUENCE (0x30), got 0x{tag:02x}"
        )));
    }

    // Iterate inner AuthenticationContext SEQUENCEs
    let mut pos = &body[..];
    while !pos.is_empty() {
        let (inner_tag, inner_body, rest) = parse_tlv_with_rest(pos)?;
        if inner_tag != 0x30 {
            return Err(SaciError::Asn1(format!(
                "expected inner SEQUENCE (0x30), got 0x{inner_tag:02x}"
            )));
        }

        // First element: contextType UTF8String (tag 0x0C)
        let (ct_tag, ct_body, inner_rest) = parse_tlv_with_rest(&inner_body)?;
        if ct_tag != 0x0C {
            return Err(SaciError::Asn1(format!(
                "expected UTF8String (0x0C) for contextType, got 0x{ct_tag:02x}"
            )));
        }
        let context_type = std::str::from_utf8(&ct_body)
            .map_err(|e| SaciError::Asn1(format!("contextType is not valid UTF-8: {e}")))?
            .to_string();

        // Second element: contextInfo UTF8String OPTIONAL
        let context_info = if !inner_rest.is_empty() {
            let (ci_tag, ci_body, _) = parse_tlv_with_rest(inner_rest)?;
            if ci_tag != 0x0C {
                return Err(SaciError::Asn1(format!(
                    "expected UTF8String (0x0C) for contextInfo, got 0x{ci_tag:02x}"
                )));
            }
            let info = std::str::from_utf8(&ci_body)
                .map_err(|e| SaciError::Asn1(format!("contextInfo is not valid UTF-8: {e}")))?
                .to_string();
            Some(info)
        } else {
            None
        };

        results.push(RawAuthenticationContext {
            context_type,
            context_info,
        });
        pos = rest;
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// XML Parsing
// ---------------------------------------------------------------------------

/// Parse a SACI `<SAMLAuthContext>` XML string into a structured object.
pub fn parse_saml_auth_context(xml: &str) -> Result<SAMLAuthContext, SaciError> {
    let mut auth_context_info = None;
    let mut id_attributes = None;

    let mut reader = Reader::from_str(xml);

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(ref e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name_str(&name_bytes);
                match local {
                    "AuthContextInfo" => {
                        auth_context_info = Some(parse_auth_context_info_attrs(e)?);
                    }
                    "IdAttributes" => {
                        id_attributes = Some(parse_id_attributes(&mut reader)?);
                    }
                    _ => {} // skip unknown elements
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name_str(&name_bytes);
                if local == "AuthContextInfo" {
                    auth_context_info = Some(parse_auth_context_info_attrs(e)?);
                }
            }
            Err(e) => {
                return Err(SaciError::Xml(format!(
                    "XML parse error at position {}: {e}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }

    Ok(SAMLAuthContext {
        auth_context_info,
        id_attributes,
    })
}

/// Parse attributes from an `<AuthContextInfo>` element.
fn parse_auth_context_info_attrs(
    e: &quick_xml::events::BytesStart<'_>,
) -> Result<AuthContextInfo, SaciError> {
    let mut identity_provider = None;
    let mut authentication_instant = None;
    let mut authn_context_class_ref = None;
    let mut assertion_ref = None;
    let mut service_id = None;

    for attr in e.attributes().flatten() {
        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
        let value = attr
            .unescape_value()
            .map_err(|e| SaciError::Xml(format!("attribute decode error: {e}")))?
            .to_string();

        match key {
            "IdentityProvider" => identity_provider = Some(value),
            "AuthenticationInstant" => authentication_instant = Some(value),
            "AuthnContextClassRef" => authn_context_class_ref = Some(value),
            "AssertionRef" => assertion_ref = Some(value),
            "ServiceID" => service_id = Some(value),
            _ => {} // ignore unknown attributes
        }
    }

    Ok(AuthContextInfo {
        identity_provider: identity_provider
            .ok_or_else(|| SaciError::MissingAttribute("IdentityProvider".into()))?,
        authentication_instant: authentication_instant
            .ok_or_else(|| SaciError::MissingAttribute("AuthenticationInstant".into()))?,
        authn_context_class_ref: authn_context_class_ref
            .ok_or_else(|| SaciError::MissingAttribute("AuthnContextClassRef".into()))?,
        assertion_ref,
        service_id,
    })
}

/// Parse the `<IdAttributes>` element and its child `<AttributeMapping>` elements.
fn parse_id_attributes(reader: &mut Reader<&[u8]>) -> Result<IdAttributes, SaciError> {
    let mut mappings = Vec::new();
    let mut depth = 1; // We're inside <IdAttributes>

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name_str(&name_bytes);
                if local == "AttributeMapping" {
                    let mapping = parse_attribute_mapping(e, reader)?;
                    mappings.push(mapping);
                } else {
                    depth += 1;
                }
            }
            Ok(Event::End(_)) => {
                depth -= 1;
                if depth == 0 {
                    break; // </IdAttributes>
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SaciError::Xml(format!("XML error in IdAttributes: {e}")));
            }
            _ => {}
        }
    }

    Ok(IdAttributes { mappings })
}

/// Parse an `<AttributeMapping>` element.
fn parse_attribute_mapping(
    start: &quick_xml::events::BytesStart<'_>,
    reader: &mut Reader<&[u8]>,
) -> Result<AttributeMapping, SaciError> {
    // Read Type and Ref attributes
    let mut mapping_type = None;
    let mut reference = None;

    for attr in start.attributes().flatten() {
        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
        let value = attr
            .unescape_value()
            .map_err(|e| SaciError::Xml(format!("attribute decode error: {e}")))?
            .to_string();

        match key {
            "Type" => {
                mapping_type = MappingType::from_str(&value);
                if mapping_type.is_none() {
                    return Err(SaciError::Xml(format!(
                        "unknown AttributeMapping Type: {value}"
                    )));
                }
            }
            "Ref" => reference = Some(value),
            _ => {}
        }
    }

    let mapping_type =
        mapping_type.ok_or_else(|| SaciError::MissingAttribute("AttributeMapping/@Type".into()))?;
    let reference =
        reference.ok_or_else(|| SaciError::MissingAttribute("AttributeMapping/@Ref".into()))?;

    // Parse child elements — looking for <saml:Attribute>
    let mut attribute = None;
    let mut depth = 1;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name_str(&name_bytes);
                if local == "Attribute" {
                    attribute = Some(parse_saml_attribute(e, reader)?);
                } else {
                    depth += 1;
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name_str(&name_bytes);
                if local == "Attribute" {
                    attribute = Some(parse_saml_attribute_empty(e)?);
                }
            }
            Ok(Event::End(_)) => {
                depth -= 1;
                if depth == 0 {
                    break; // </AttributeMapping>
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SaciError::Xml(format!(
                    "XML error in AttributeMapping: {e}"
                )));
            }
            _ => {}
        }
    }

    let attribute = attribute.ok_or_else(|| SaciError::MissingElement("saml:Attribute".into()))?;

    Ok(AttributeMapping {
        mapping_type,
        reference,
        attribute,
    })
}

/// Parse a `<saml:Attribute>` element (with children).
fn parse_saml_attribute(
    start: &quick_xml::events::BytesStart<'_>,
    reader: &mut Reader<&[u8]>,
) -> Result<SamlAttribute, SaciError> {
    let mut attr = parse_saml_attribute_attrs(start)?;

    // Read child <saml:AttributeValue> elements
    let mut depth = 1;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name_str(&name_bytes);
                if local == "AttributeValue" {
                    let text = read_element_text(reader)?;
                    attr.values.push(text.trim().to_string());
                } else {
                    depth += 1;
                }
            }
            Ok(Event::End(_)) => {
                depth -= 1;
                if depth == 0 {
                    break; // </saml:Attribute>
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SaciError::Xml(format!("XML error in Attribute: {e}")));
            }
            _ => {}
        }
    }

    Ok(attr)
}

/// Parse a `<saml:Attribute/>` empty element (no children).
fn parse_saml_attribute_empty(
    start: &quick_xml::events::BytesStart<'_>,
) -> Result<SamlAttribute, SaciError> {
    parse_saml_attribute_attrs(start)
}

/// Parse the XML attributes of a `<saml:Attribute>` element.
fn parse_saml_attribute_attrs(
    e: &quick_xml::events::BytesStart<'_>,
) -> Result<SamlAttribute, SaciError> {
    let mut name = None;
    let mut name_format = None;
    let mut friendly_name = None;

    for attr in e.attributes().flatten() {
        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
        let value = attr
            .unescape_value()
            .map_err(|e| SaciError::Xml(format!("attribute decode error: {e}")))?
            .to_string();

        match key {
            "Name" => name = Some(value),
            "NameFormat" => name_format = Some(value),
            "FriendlyName" => friendly_name = Some(value),
            _ => {}
        }
    }

    Ok(SamlAttribute {
        name,
        name_format,
        friendly_name,
        values: Vec::new(),
    })
}

/// Read the text content of the current element until its closing tag.
fn read_element_text(reader: &mut Reader<&[u8]>) -> Result<String, SaciError> {
    let mut text = String::new();
    let mut depth = 1;

    loop {
        match reader.read_event() {
            Ok(Event::Text(e)) => {
                let t = e
                    .unescape()
                    .map_err(|e| SaciError::Xml(format!("text unescape error: {e}")))?;
                text.push_str(&t);
            }
            Ok(Event::Start(_)) => {
                depth += 1;
            }
            Ok(Event::End(_)) => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SaciError::Xml(format!(
                    "XML error reading element text: {e}"
                )));
            }
            _ => {}
        }
    }

    Ok(text)
}

// ---------------------------------------------------------------------------
// DER helpers (reused pattern from other modules)
// ---------------------------------------------------------------------------

fn parse_tlv(data: &[u8]) -> Result<(u8, Vec<u8>), SaciError> {
    let (tag, body, _) = parse_tlv_with_rest(data)?;
    Ok((tag, body.to_vec()))
}

fn parse_tlv_with_rest(data: &[u8]) -> Result<(u8, Vec<u8>, &[u8]), SaciError> {
    if data.is_empty() {
        return Err(SaciError::Asn1("empty input".into()));
    }
    let tag = data[0];
    let (len, header_len) = parse_der_length(&data[1..])?;
    let total_header = 1 + header_len;
    if total_header + len > data.len() {
        return Err(SaciError::Asn1(format!(
            "TLV overflow: need {}, have {}",
            total_header + len,
            data.len()
        )));
    }
    let value = &data[total_header..total_header + len];
    let rest = &data[total_header + len..];
    Ok((tag, value.to_vec(), rest))
}

fn parse_der_length(data: &[u8]) -> Result<(usize, usize), SaciError> {
    if data.is_empty() {
        return Err(SaciError::Asn1("empty length".into()));
    }
    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else if first == 0x80 {
        Err(SaciError::Asn1("indefinite length not supported".into()))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || 1 + num_bytes > data.len() {
            return Err(SaciError::Asn1("length encoding error".into()));
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Ok((len, 1 + num_bytes))
    }
}

/// Extract the local name from a possibly namespaced XML element name.
///
/// E.g., `"saci:AuthContextInfo"` → `"AuthContextInfo"`,
/// `"saml:Attribute"` → `"Attribute"`, `"SAMLAuthContext"` → `"SAMLAuthContext"`.
fn local_name_str(name: &[u8]) -> &str {
    let s = std::str::from_utf8(name).unwrap_or("");
    if let Some(pos) = s.rfind(':') {
        &s[pos + 1..]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Example SACI XML from Sweden Connect test data.
    const EXAMPLE_XML: &str = r#"<SAMLAuthContext xmlns="http://id.elegnamnden.se/auth-cont/1.0/saci" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><AuthContextInfo IdentityProvider="http://dev.test.swedenconnect.se/idp" AuthenticationInstant="2023-01-11T13:46:00.435+01:00" AuthnContextClassRef="http://id.elegnamnden.se/loa/1.0/loa3" AssertionRef="_8db6eb9e8dc043d554eaa0dad145cfda" ServiceID="https://eid2cssp.3xasecurity.com/sign"/><IdAttributes><AttributeMapping Type="rdn" Ref="2.5.4.5"><saml:Attribute Name="urn:oid:1.2.752.29.4.13" FriendlyName="personalIdentityNumber"><saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">197010632391</saml:AttributeValue></saml:Attribute></AttributeMapping><AttributeMapping Type="rdn" Ref="2.5.4.6"><saml:Attribute FriendlyName="country"><saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">SE</saml:AttributeValue></saml:Attribute></AttributeMapping><AttributeMapping Type="rdn" Ref="2.5.4.42"><saml:Attribute Name="urn:oid:2.5.4.42" FriendlyName="givenName"><saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Sixten</saml:AttributeValue></saml:Attribute></AttributeMapping><AttributeMapping Type="rdn" Ref="2.5.4.4"><saml:Attribute Name="urn:oid:2.5.4.4" FriendlyName="sn"><saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">von Samordnungsnummer</saml:AttributeValue></saml:Attribute></AttributeMapping><AttributeMapping Type="rdn" Ref="2.5.4.3"><saml:Attribute Name="urn:oid:2.16.840.1.113730.3.1.241" FriendlyName="displayName"><saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Sixten von Samordnungsnummer</saml:AttributeValue></saml:Attribute></AttributeMapping></IdAttributes></SAMLAuthContext>"#;

    #[test]
    fn test_parse_example_xml() {
        let ctx = parse_saml_auth_context(EXAMPLE_XML).unwrap();

        // AuthContextInfo
        let info = ctx.auth_context_info.as_ref().unwrap();
        assert_eq!(
            info.identity_provider,
            "http://dev.test.swedenconnect.se/idp"
        );
        assert_eq!(
            info.authn_context_class_ref,
            "http://id.elegnamnden.se/loa/1.0/loa3"
        );
        assert_eq!(info.authentication_instant, "2023-01-11T13:46:00.435+01:00");
        assert_eq!(
            info.assertion_ref.as_deref(),
            Some("_8db6eb9e8dc043d554eaa0dad145cfda")
        );
        assert_eq!(
            info.service_id.as_deref(),
            Some("https://eid2cssp.3xasecurity.com/sign")
        );
    }

    #[test]
    fn test_parse_id_attributes() {
        let ctx = parse_saml_auth_context(EXAMPLE_XML).unwrap();
        let attrs = ctx.id_attributes.as_ref().unwrap();

        assert_eq!(attrs.mappings.len(), 5);

        // First mapping: personalIdentityNumber → serialNumber (2.5.4.5)
        let m0 = &attrs.mappings[0];
        assert_eq!(m0.mapping_type, MappingType::Rdn);
        assert_eq!(m0.reference, "2.5.4.5");
        assert_eq!(
            m0.attribute.name.as_deref(),
            Some("urn:oid:1.2.752.29.4.13")
        );
        assert_eq!(
            m0.attribute.friendly_name.as_deref(),
            Some("personalIdentityNumber")
        );
        assert_eq!(m0.attribute.values, vec!["197010632391"]);

        // Second mapping: country → countryName (2.5.4.6)
        let m1 = &attrs.mappings[1];
        assert_eq!(m1.mapping_type, MappingType::Rdn);
        assert_eq!(m1.reference, "2.5.4.6");
        assert_eq!(m1.attribute.name, None);
        assert_eq!(m1.attribute.friendly_name.as_deref(), Some("country"));
        assert_eq!(m1.attribute.values, vec!["SE"]);

        // Third mapping: givenName (2.5.4.42)
        let m2 = &attrs.mappings[2];
        assert_eq!(m2.reference, "2.5.4.42");
        assert_eq!(m2.attribute.values, vec!["Sixten"]);

        // Fourth mapping: surname (2.5.4.4)
        let m3 = &attrs.mappings[3];
        assert_eq!(m3.reference, "2.5.4.4");
        assert_eq!(m3.attribute.values, vec!["von Samordnungsnummer"]);

        // Fifth mapping: displayName → CN (2.5.4.3)
        let m4 = &attrs.mappings[4];
        assert_eq!(m4.reference, "2.5.4.3");
        assert_eq!(m4.attribute.values, vec!["Sixten von Samordnungsnummer"]);
    }

    #[test]
    fn test_parse_minimal_xml() {
        // Minimal valid SACI XML — no AuthContextInfo, no IdAttributes
        let xml = r#"<SAMLAuthContext xmlns="http://id.elegnamnden.se/auth-cont/1.0/saci"/>"#;
        let ctx = parse_saml_auth_context(xml).unwrap();
        assert!(ctx.auth_context_info.is_none());
        assert!(ctx.id_attributes.is_none());
    }

    #[test]
    fn test_parse_auth_context_info_only() {
        let xml = r#"<SAMLAuthContext xmlns="http://id.elegnamnden.se/auth-cont/1.0/saci">
            <AuthContextInfo
                IdentityProvider="http://example.com/idp"
                AuthenticationInstant="2024-06-15T10:30:00Z"
                AuthnContextClassRef="http://example.com/loa3"/>
        </SAMLAuthContext>"#;

        let ctx = parse_saml_auth_context(xml).unwrap();
        let info = ctx.auth_context_info.unwrap();
        assert_eq!(info.identity_provider, "http://example.com/idp");
        assert_eq!(info.authentication_instant, "2024-06-15T10:30:00Z");
        assert_eq!(info.authn_context_class_ref, "http://example.com/loa3");
        assert!(info.assertion_ref.is_none());
        assert!(info.service_id.is_none());
        assert!(ctx.id_attributes.is_none());
    }

    #[test]
    fn test_mapping_type_roundtrip() {
        assert_eq!(MappingType::from_str("rdn"), Some(MappingType::Rdn));
        assert_eq!(MappingType::from_str("san"), Some(MappingType::San));
        assert_eq!(MappingType::from_str("sda"), Some(MappingType::Sda));
        assert_eq!(MappingType::from_str("unknown"), None);

        assert_eq!(MappingType::Rdn.as_str(), "rdn");
        assert_eq!(MappingType::San.as_str(), "san");
        assert_eq!(MappingType::Sda.as_str(), "sda");
    }

    #[test]
    fn test_mapping_type_display() {
        assert_eq!(format!("{}", MappingType::Rdn), "rdn");
        assert_eq!(format!("{}", MappingType::San), "san");
    }

    #[test]
    fn test_local_name_extraction() {
        assert_eq!(local_name_str(b"saci:AuthContextInfo"), "AuthContextInfo");
        assert_eq!(local_name_str(b"saml:Attribute"), "Attribute");
        assert_eq!(local_name_str(b"SAMLAuthContext"), "SAMLAuthContext");
        assert_eq!(local_name_str(b""), "");
    }

    #[test]
    fn test_decode_authentication_contexts_synthetic() {
        // Build a synthetic ASN.1 AuthenticationContexts manually:
        // SEQUENCE {
        //   SEQUENCE {
        //     UTF8String "http://id.elegnamnden.se/auth-cont/1.0/saci"
        //     UTF8String "<SAMLAuthContext/>"
        //   }
        // }
        let context_type = SACI_CONTEXT_TYPE.as_bytes();
        let context_info =
            b"<SAMLAuthContext xmlns=\"http://id.elegnamnden.se/auth-cont/1.0/saci\"/>";

        let ct_tlv = encode_tlv(0x0C, context_type);
        let ci_tlv = encode_tlv(0x0C, context_info);

        let mut inner_body = Vec::new();
        inner_body.extend_from_slice(&ct_tlv);
        inner_body.extend_from_slice(&ci_tlv);
        let inner_seq = encode_tlv(0x30, &inner_body);

        let outer_seq = encode_tlv(0x30, &inner_seq);

        let raw = decode_authentication_contexts(&outer_seq).unwrap();
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].context_type, SACI_CONTEXT_TYPE);
        assert!(raw[0].context_info.is_some());
    }

    #[test]
    fn test_missing_auth_context_info_attribute() {
        // Missing required IdentityProvider attribute
        let xml = r#"<SAMLAuthContext xmlns="http://id.elegnamnden.se/auth-cont/1.0/saci">
            <AuthContextInfo
                AuthenticationInstant="2024-06-15T10:30:00Z"
                AuthnContextClassRef="http://example.com/loa3"/>
        </SAMLAuthContext>"#;

        let result = parse_saml_auth_context(xml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SaciError::MissingAttribute(_)));
    }

    /// Encode a TLV for test data construction.
    fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 5 + value.len());
        out.push(tag);
        let len = value.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xFF {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
        out.extend_from_slice(value);
        out
    }
}
