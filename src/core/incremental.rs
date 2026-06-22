//! Custom byte-level incremental PDF writer.
//!
//! PDF signing requires appending new objects to an existing PDF via an
//! incremental update, with **exact control** over byte offsets. This writer
//! handles serializing new/modified objects, building the cross-reference table,
//! and tracking offsets for ByteRange and /Contents placement.
//!
//! We do NOT use lopdf's `IncrementalDocument` for writing because it doesn't
//! expose the byte-offset hooks needed for signing.

use std::io::Write;

use lopdf::{Dictionary, Object, ObjectId};

use crate::core::byte_range::ByteRange;
use crate::error::CoreError;

/// Tracks a new object to be written in the incremental update.
#[derive(Debug)]
struct PendingObject {
    id: ObjectId,
    object: Object,
}

/// Byte-level incremental PDF writer for signing.
///
/// Appends new objects, xref table, and trailer to an existing PDF byte stream,
/// while tracking exact byte offsets for ByteRange/Contents backpatching.
pub struct IncrementalWriter {
    /// The original PDF bytes (read-only)
    original: Vec<u8>,
    /// Objects to append
    pending_objects: Vec<PendingObject>,
    /// The object ID of the signature dictionary (for offset tracking)
    sig_dict_id: Option<ObjectId>,
    /// Size reserved for hex-encoded /Contents (number of hex chars)
    contents_hex_size: usize,
    /// Previous trailer's /Size value
    prev_size: u32,
    /// Byte offset of the previous xref table (for /Prev in trailer)
    prev_xref_offset: usize,
    /// The root object ID (catalog)
    root_id: ObjectId,
    /// The trailer `/ID` array to carry forward, if the original had one.
    id: Option<Object>,
    /// The trailer `/Encrypt` entry to carry forward, if the original had one.
    encrypt: Option<Object>,
    /// When true, write the incremental cross-reference section as an XRef
    /// stream (matching a PDF 1.5+ source that uses cross-reference streams)
    /// rather than a classic `xref` table + `trailer`.
    use_xref_stream: bool,
}

impl IncrementalWriter {
    /// Create a new incremental writer.
    ///
    /// - `original`: the complete original PDF bytes
    /// - `prev_size`: the `/Size` from the original trailer (next object number)
    /// - `prev_xref_offset`: byte offset of the original xref table (for `/Prev`)
    /// - `root_id`: the `/Root` catalog object ID
    /// - `contents_hex_size`: how many hex characters to reserve for `/Contents`
    pub fn new(
        original: Vec<u8>,
        prev_size: u32,
        prev_xref_offset: usize,
        root_id: ObjectId,
        contents_hex_size: usize,
    ) -> Self {
        Self {
            original,
            pending_objects: Vec::new(),
            sig_dict_id: None,
            contents_hex_size,
            prev_size,
            prev_xref_offset,
            root_id,
            id: None,
            encrypt: None,
            use_xref_stream: false,
        }
    }

    /// Configure trailer carry-over and cross-reference format from the source
    /// document's [`PdfMetadata`](super::parser::PdfMetadata).
    ///
    /// - `id` / `encrypt`: the original trailer's `/ID` and `/Encrypt`, written
    ///   into the new cross-reference section so the update stays structurally
    ///   faithful (dropping them corrupts encrypted/PDF-A documents).
    /// - `use_xref_stream`: when the source's latest xref section is a
    ///   cross-reference stream, emit the update as an XRef stream too.
    pub fn set_trailer_meta(
        &mut self,
        id: Option<Object>,
        encrypt: Option<Object>,
        use_xref_stream: bool,
    ) {
        self.id = id;
        self.encrypt = encrypt;
        self.use_xref_stream = use_xref_stream;
    }

    /// Add an object to be written in the incremental update.
    pub fn add_object(&mut self, id: ObjectId, object: Object) {
        self.pending_objects.push(PendingObject { id, object });
    }

    /// Mark which object ID is the signature dictionary.
    /// This is needed so the writer can track its /ByteRange and /Contents offsets.
    pub fn set_sig_dict_id(&mut self, id: ObjectId) {
        self.sig_dict_id = Some(id);
    }

    /// Write the incremental update and return the complete PDF bytes
    /// along with the ByteRange tracking info needed for backpatching.
    pub fn write(self) -> Result<(Vec<u8>, ByteRange), CoreError> {
        let mut buf = self.original.clone();

        // Ensure we start on a newline
        if buf.last() != Some(&b'\n') {
            buf.push(b'\n');
        }

        let mut xref_entries: Vec<(ObjectId, usize)> = Vec::new();
        let mut byte_range = None;

        // Write each pending object
        for pending in &self.pending_objects {
            let offset = buf.len();
            xref_entries.push((pending.id, offset));

            if Some(pending.id) == self.sig_dict_id {
                // Special handling for signature dictionary — we need to track
                // exact offsets of ByteRange and Contents placeholders
                byte_range = Some(self.write_sig_dict(&mut buf, pending.id, &pending.object)?);
            } else {
                self.write_object(&mut buf, pending.id, &pending.object)?;
            }
        }

        let byte_range = byte_range.ok_or(CoreError::InvalidStructure(
            "no signature dictionary found in pending objects".into(),
        ))?;

        if self.use_xref_stream {
            // PDF 1.5+ source uses cross-reference streams: the update must be
            // an XRef stream object, not a classic `xref`/`trailer`.
            self.write_xref_stream_section(&mut buf, &xref_entries)?;
        } else {
            // Classic cross-reference table + trailer.
            let xref_offset = buf.len();
            self.write_xref(&mut buf, &xref_entries)?;
            let max_obj = xref_entries.iter().map(|(id, _)| id.0).max().unwrap_or(0);
            let size = self.prev_size.max(max_obj.saturating_add(1));
            self.write_trailer(&mut buf, size, xref_offset)?;
        }

        // Backpatch ByteRange with final values
        let total_len = buf.len();
        byte_range.backpatch(&mut buf, total_len)?;

        Ok((buf, byte_range))
    }

    /// Group `(object_number)`-sorted entries into contiguous cross-reference
    /// subsections, returned as `(start_object_number, entries)` runs.
    fn group_subsections(sorted: &[(ObjectId, usize)]) -> Vec<(u32, Vec<(ObjectId, usize)>)> {
        let mut sections: Vec<(u32, Vec<(ObjectId, usize)>)> = Vec::new();
        for entry in sorted {
            let num = entry.0 .0;
            match sections.last_mut() {
                Some((start, run)) if *start + run.len() as u32 == num => run.push(*entry),
                _ => sections.push((num, vec![*entry])),
            }
        }
        sections
    }

    /// Write a non-signature object.
    fn write_object(
        &self,
        buf: &mut Vec<u8>,
        id: ObjectId,
        object: &Object,
    ) -> Result<(), CoreError> {
        writeln!(buf, "{} {} obj", id.0, id.1)
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        self.serialize_object(buf, object)?;
        write!(buf, "\nendobj\n")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        Ok(())
    }

    /// Write the signature dictionary with tracked offsets for ByteRange and Contents.
    fn write_sig_dict(
        &self,
        buf: &mut Vec<u8>,
        id: ObjectId,
        object: &Object,
    ) -> Result<ByteRange, CoreError> {
        writeln!(buf, "{} {} obj", id.0, id.1)
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        // We need to write the dictionary manually to track offsets
        let dict = match object {
            Object::Dictionary(d) => d,
            _ => {
                return Err(CoreError::InvalidStructure(
                    "signature dictionary is not a Dictionary".into(),
                ))
            }
        };

        writeln!(buf, "<<")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        let mut byte_range_offset = 0;
        let mut byte_range_length = 0;
        let mut contents_offset = 0;

        for (key, value) in dict.iter() {
            let key_str = std::str::from_utf8(key).unwrap_or("?");
            write!(buf, "/{key_str} ")
                .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

            if key_str == "ByteRange" {
                // Write the fixed-width placeholder and track its offset
                let placeholder = ByteRange::placeholder_string();
                byte_range_offset = buf.len();
                byte_range_length = placeholder.len();
                write!(buf, "{placeholder}")
                    .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
            } else if key_str == "Contents" {
                // Write the hex placeholder and track its offset
                write!(buf, "<")
                    .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
                contents_offset = buf.len();
                // Write `contents_hex_size` zero hex chars
                let hex_placeholder = "0".repeat(self.contents_hex_size);
                write!(buf, "{hex_placeholder}")
                    .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
                write!(buf, ">")
                    .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
            } else {
                self.serialize_object(buf, value)?;
            }
            writeln!(buf).map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        }

        write!(buf, ">>\nendobj\n")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        Ok(ByteRange {
            placeholder_offset: byte_range_offset,
            placeholder_length: byte_range_length,
            contents_offset,
            contents_length: self.contents_hex_size,
        })
    }

    /// Serialize a lopdf Object to bytes.
    fn serialize_object(&self, buf: &mut Vec<u8>, object: &Object) -> Result<(), CoreError> {
        match object {
            Object::Null => write!(buf, "null"),
            Object::Boolean(b) => write!(buf, "{}", if *b { "true" } else { "false" }),
            Object::Integer(i) => write!(buf, "{i}"),
            Object::Real(f) => write!(buf, "{f}"),
            Object::Name(n) => {
                write!(buf, "/")?;
                buf.extend_from_slice(n);
                Ok(())
            }
            Object::String(s, format) => match format {
                lopdf::StringFormat::Literal => {
                    write!(buf, "(")?;
                    buf.extend_from_slice(s);
                    write!(buf, ")")
                }
                lopdf::StringFormat::Hexadecimal => {
                    write!(buf, "<")?;
                    for byte in s {
                        write!(buf, "{byte:02X}")?;
                    }
                    write!(buf, ">")
                }
            },
            Object::Array(arr) => {
                write!(buf, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(buf, " ")?;
                    }
                    self.serialize_object(buf, item)?;
                }
                write!(buf, "]")
            }
            Object::Dictionary(dict) => {
                write!(buf, "<<")?;
                for (key, value) in dict.iter() {
                    write!(buf, "/")?;
                    buf.extend_from_slice(key);
                    write!(buf, " ")?;
                    self.serialize_object(buf, value)?;
                }
                write!(buf, ">>")
            }
            Object::Reference(id) => write!(buf, "{} {} R", id.0, id.1),
            Object::Stream(stream) => {
                self.serialize_object(buf, &Object::Dictionary(stream.dict.clone()))?;
                write!(buf, "\nstream\n")?;
                buf.extend_from_slice(&stream.content);
                write!(buf, "\nendstream")
            }
        }
        .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))
    }

    /// Write the classic cross-reference table for the new objects.
    ///
    /// Emits the mandatory free-list head (object 0) followed by contiguous
    /// subsections grouping consecutive object numbers, per PDF 32000-1 §7.5.4.
    fn write_xref(
        &self,
        buf: &mut Vec<u8>,
        entries: &[(ObjectId, usize)],
    ) -> Result<(), CoreError> {
        writeln!(buf, "xref")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        // Sort entries by object number and group into contiguous subsections.
        let mut sorted: Vec<_> = entries.to_vec();
        sorted.sort_by_key(|(id, _)| id.0);
        let sections = Self::group_subsections(&sorted);

        // Free-list head: object 0, the head of the linked list of free
        // entries, generation 65535, marked free. Conformant readers expect it.
        writeln!(buf, "0 1")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        writeln!(buf, "{:010} {:05} f ", 0, 65535)
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        for (start, run) in &sections {
            writeln!(buf, "{} {}", start, run.len())
                .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
            for (id, offset) in run {
                writeln!(buf, "{:010} {:05} n ", offset, id.1)
                    .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
            }
        }

        Ok(())
    }

    /// Write the classic trailer dictionary, carrying forward `/ID` and
    /// `/Encrypt` from the source document.
    fn write_trailer(
        &self,
        buf: &mut Vec<u8>,
        size: u32,
        xref_offset: usize,
    ) -> Result<(), CoreError> {
        let mut trailer = Dictionary::new();
        trailer.set("Size", Object::Integer(size as i64));
        trailer.set("Root", Object::Reference(self.root_id));
        trailer.set("Prev", Object::Integer(self.prev_xref_offset as i64));
        if let Some(id) = &self.id {
            trailer.set("ID", id.clone());
        }
        if let Some(encrypt) = &self.encrypt {
            trailer.set("Encrypt", encrypt.clone());
        }

        writeln!(buf, "trailer")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        self.serialize_object(buf, &Object::Dictionary(trailer))?;
        write!(buf, "\nstartxref\n{xref_offset}\n%%EOF\n")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        Ok(())
    }

    /// Write the incremental cross-reference section as an XRef **stream**
    /// object (PDF 32000-1 §7.5.8), used when the source document's latest
    /// cross-reference section is itself a stream.
    ///
    /// The XRef stream is an object, so it allocates its own object number and
    /// includes a self-referential entry. We emit an uncompressed stream (no
    /// `/Filter`) with `/W [1 w2 2]` field widths, which conformant readers
    /// (including Acrobat and lopdf) accept.
    fn write_xref_stream_section(
        &self,
        buf: &mut Vec<u8>,
        entries: &[(ObjectId, usize)],
    ) -> Result<(), CoreError> {
        // The XRef stream itself is a new object; it takes the next free
        // object number above everything already written.
        let max_pending = entries.iter().map(|(id, _)| id.0).max().unwrap_or(0);
        let xref_num = max_pending.max(self.prev_size.saturating_sub(1)) + 1;
        let xref_offset = buf.len();

        // All entries, including the mandatory free-list head (object 0) and
        // the XRef stream's own self-reference.
        let mut all: Vec<(ObjectId, usize)> = entries.to_vec();
        all.push(((0, 65535), 0));
        all.push(((xref_num, 0), xref_offset));
        all.sort_by_key(|(id, _)| id.0);

        // Field widths: type (1 byte), offset (w2 bytes), generation (2 bytes).
        let max_offset = all.iter().map(|(_, off)| *off).max().unwrap_or(0);
        let w2 = bytes_for(max_offset as u64);
        let w3: usize = 2;

        // Binary cross-reference data: object 0 is the free-list head (type 0),
        // all other entries written by this update are in-use objects (type 1).
        let mut data: Vec<u8> = Vec::with_capacity(all.len() * (1 + w2 + w3));
        for (id, offset) in &all {
            if id.0 == 0 {
                data.push(0); // type 0: free object, next free object number 0
                data.extend_from_slice(&be_bytes(0, w2));
                data.extend_from_slice(&be_bytes(65535, w3));
            } else {
                data.push(1); // type 1: in-use object at a byte offset
                data.extend_from_slice(&be_bytes(*offset as u64, w2));
                data.extend_from_slice(&be_bytes(id.1 as u64, w3));
            }
        }

        // /Index subsections grouping contiguous object numbers.
        let sections = Self::group_subsections(&all);
        let mut index: Vec<Object> = Vec::with_capacity(sections.len() * 2);
        for (start, run) in &sections {
            index.push(Object::Integer(*start as i64));
            index.push(Object::Integer(run.len() as i64));
        }

        let mut dict = Dictionary::new();
        dict.set("Type", Object::Name(b"XRef".to_vec()));
        // /Size must exceed the highest object number, which is the XRef stream.
        dict.set("Size", Object::Integer((xref_num + 1) as i64));
        dict.set("Root", Object::Reference(self.root_id));
        dict.set("Prev", Object::Integer(self.prev_xref_offset as i64));
        dict.set(
            "W",
            Object::Array(vec![
                Object::Integer(1),
                Object::Integer(w2 as i64),
                Object::Integer(w3 as i64),
            ]),
        );
        dict.set("Index", Object::Array(index));
        dict.set("Length", Object::Integer(data.len() as i64));
        if let Some(id) = &self.id {
            dict.set("ID", id.clone());
        }
        if let Some(encrypt) = &self.encrypt {
            dict.set("Encrypt", encrypt.clone());
        }

        // Serialize the XRef stream object. The cross-reference data is never
        // encrypted, so it is written verbatim regardless of /Encrypt.
        writeln!(buf, "{} {} obj", xref_num, 0)
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        self.serialize_object(buf, &Object::Dictionary(dict))?;
        write!(buf, "\nstream\n")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        buf.extend_from_slice(&data);
        write!(buf, "\nendstream\nendobj\n")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        write!(buf, "startxref\n{xref_offset}\n%%EOF\n")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        Ok(())
    }
}

/// Number of bytes needed to big-endian-encode `value` (minimum 1).
fn bytes_for(value: u64) -> usize {
    let mut n = 1;
    let mut v = value >> 8;
    while v > 0 {
        n += 1;
        v >>= 8;
    }
    n
}

/// Big-endian encode `value` into exactly `width` bytes (left zero-padded).
fn be_bytes(value: u64, width: usize) -> Vec<u8> {
    let full = value.to_be_bytes();
    full[8 - width..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig_dict() -> Object {
        let mut dict = Dictionary::new();
        dict.set(
            "ByteRange",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(0),
            ]),
        );
        dict.set(
            "Contents",
            Object::String(vec![0; 8], lopdf::StringFormat::Hexadecimal),
        );
        Object::Dictionary(dict)
    }

    #[test]
    fn classic_trailer_size_ignores_rewritten_existing_objects() {
        let mut writer = IncrementalWriter::new(b"%PDF-1.4\n".to_vec(), 10, 4, (1, 0), 16);
        writer.set_sig_dict_id((5, 0));
        writer.add_object((5, 0), sig_dict());
        writer.add_object((1, 0), Object::Dictionary(Dictionary::new()));

        let (pdf, _) = writer.write().expect("write incremental update");
        let text = String::from_utf8_lossy(&pdf);

        assert!(
            text.contains("/Size 10"),
            "trailer /Size must remain 10: {text}"
        );
        assert!(
            !text.contains("/Size 12"),
            "rewritten objects must not inflate /Size: {text}"
        );
    }

    #[test]
    fn xref_stream_contains_free_object_zero() {
        let mut writer = IncrementalWriter::new(b"%PDF-1.5\n".to_vec(), 10, 4, (1, 0), 16);
        writer.set_trailer_meta(None, None, true);
        writer.set_sig_dict_id((5, 0));
        writer.add_object((5, 0), sig_dict());

        let (pdf, _) = writer.write().expect("write xref stream update");
        let text = String::from_utf8_lossy(&pdf);
        assert!(
            text.contains("/Index [0 1"),
            "xref stream must index object 0: {text}"
        );

        let stream_start = pdf
            .windows(b"stream\n".len())
            .position(|window| window == b"stream\n")
            .expect("xref stream marker")
            + b"stream\n".len();
        assert_eq!(
            pdf[stream_start], 0,
            "object 0 xref-stream entry must be free"
        );
    }
}
