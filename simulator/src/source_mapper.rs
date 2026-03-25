// Copyright 2026 Erst Users
// SPDX-License-Identifier: Apache-2.0

use crate::git_detector::GitRepository;
use crate::stack_trace::StackFrame;
use gimli::{self, ColumnType, Dwarf, EndianSlice, Reader, RunTimeEndian, SectionId};
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;

pub struct SourceMapper {
    contracts: HashMap<String, ContractSymbols>,
}

const ROOT_CONTRACT_KEY: &str = "__root__";

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
    pub column_end: Option<u32>,
    pub github_link: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedLineEntry {
    start: u64,
    end: Option<u64>,
    location: SourceLocation,
}

#[derive(Debug, Clone)]
struct ContractSymbols {
    has_symbols: bool,
    line_cache: Vec<CachedLineEntry>,
    git_repo: Option<GitRepository>,
}

impl SourceMapper {
    /// Creates a new SourceMapper with caching enabled
    pub fn new(wasm_bytes: Vec<u8>) -> Self {
        Self::new_with_options(wasm_bytes, false)
    }

    /// Creates a new SourceMapper, bypassing the cache when `no_cache` is true.
    /// When `no_cache` is true, WASM debug symbols are always re-parsed from scratch.
    pub fn new_with_options(wasm_bytes: Vec<u8>, no_cache: bool) -> Self {
        let mut contracts = HashMap::new();
        contracts.insert(
            ROOT_CONTRACT_KEY.to_string(),
            Self::load_contract_symbols(wasm_bytes, no_cache),
        );

        Self { contracts }
    }

    /// Creates a SourceMapper that can resolve offsets for the root contract
    /// and any number of additional contracts keyed by contract ID.
    pub fn new_multi_with_options(
        root_wasm_bytes: Option<Vec<u8>>,
        contract_wasms: HashMap<String, Vec<u8>>,
        no_cache: bool,
    ) -> Self {
        let mut contracts = HashMap::new();

        if let Some(root_wasm_bytes) = root_wasm_bytes {
            contracts.insert(
                ROOT_CONTRACT_KEY.to_string(),
                Self::load_contract_symbols(root_wasm_bytes, no_cache),
            );
        }

        for (contract_id, wasm_bytes) in contract_wasms {
            contracts.insert(contract_id, Self::load_contract_symbols(wasm_bytes, no_cache));
        }

        Self { contracts }
    }

    fn load_contract_symbols(wasm_bytes: Vec<u8>, no_cache: bool) -> ContractSymbols {
        if no_cache {
            eprintln!("--no-cache: skipping cache, re-parsing WASM symbols from scratch.");
        }
        let has_symbols = Self::check_debug_symbols(&wasm_bytes);
        let git_repo = Self::detect_git_repository();

        let line_cache = if has_symbols {
            Self::build_line_cache(&wasm_bytes).unwrap_or_default()
        } else {
            Vec::new()
        };

        ContractSymbols {
            has_symbols,
            line_cache,
            git_repo,
        }
    }

    /// Backward-compatible constructor used by tests.
    #[allow(dead_code)]
    pub fn new_with_cache(wasm_bytes: Vec<u8>, _cache_dir: PathBuf) -> Self {
        Self::new(wasm_bytes)
    }

    fn detect_git_repository() -> Option<GitRepository> {
        let current_dir = std::env::current_dir().ok()?;
        GitRepository::detect(&current_dir)
    }

    fn check_debug_symbols(wasm_bytes: &[u8]) -> bool {
        if let Ok(obj_file) = object::File::parse(wasm_bytes) {
            obj_file.section_by_name(".debug_info").is_some()
                && obj_file.section_by_name(".debug_line").is_some()
        } else {
            false
        }
    }

    #[allow(deprecated)]
    fn build_line_cache(wasm_bytes: &[u8]) -> Result<Vec<CachedLineEntry>, String> {
        let obj_file = object::File::parse(wasm_bytes)
            .map_err(|err| format!("failed to parse wasm object: {err}"))?;
        let endian = if obj_file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };

        let dwarf_sections = Dwarf::load(|id: SectionId| -> Result<Cow<'_, [u8]>, gimli::Error> {
            if let Some(section) = obj_file.section_by_name(id.name()) {
                match section.uncompressed_data() {
                    Ok(data) => Ok(data),
                    Err(_) => Ok(Cow::Borrowed(&[])),
                }
            } else {
                Ok(Cow::Borrowed(&[]))
            }
        })
        .map_err(|err| format!("failed to load DWARF: {err}"))?;

        let dwarf = dwarf_sections.borrow(|section| EndianSlice::new(section.as_ref(), endian));
        Self::extract_line_entries(&dwarf)
            .map_err(|err| format!("failed to parse .debug_line: {err}"))
    }

    fn extract_line_entries<R>(dwarf: &Dwarf<R>) -> Result<Vec<CachedLineEntry>, gimli::Error>
    where
        R: Reader,
    {
        let mut cache = Vec::new();
        let mut units = dwarf.units();

        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let Some(program) = unit.line_program.clone() else {
                continue;
            };

            let (program, sequences) = program.sequences()?;
            for sequence in sequences {
                let mut rows = program.resume_from(&sequence);
                let mut pending: Option<(u64, SourceLocation)> = None;

                while let Some((line_header, row)) = rows.next_row()? {
                    if row.end_sequence() {
                        if let Some((start, location)) = pending.take() {
                            cache.push(CachedLineEntry {
                                start,
                                end: Some(row.address()),
                                location,
                            });
                        }
                        continue;
                    }

                    let Some(file) = row.file(line_header) else {
                        continue;
                    };

                    let Some(file_name) =
                        Self::attr_value_to_string(dwarf, &unit, file.path_name())
                    else {
                        continue;
                    };

                    let dir_name = file
                        .directory(line_header)
                        .and_then(|dir| Self::attr_value_to_string(dwarf, &unit, dir));

                    let file_name = if let Some(dir) = dir_name {
                        if !dir.is_empty() && !file_name.starts_with('/') {
                            format!("{dir}/{file_name}")
                        } else {
                            file_name
                        }
                    } else {
                        file_name
                    };

                    let Some(line) = row.line() else {
                        continue;
                    };

                    let column = match row.column() {
                        ColumnType::LeftEdge => None,
                        ColumnType::Column(column) => Some(column.get() as u32),
                    };

                    let location = SourceLocation {
                        file: file_name,
                        line: line.get() as u32,
                        column,
                        column_end: None,
                        github_link: None,
                    };

                    if let Some((start, prev_location)) = pending.replace((row.address(), location))
                    {
                        cache.push(CachedLineEntry {
                            start,
                            end: Some(row.address()),
                            location: prev_location,
                        });
                    }
                }

                if let Some((start, location)) = pending.take() {
                    cache.push(CachedLineEntry {
                        start,
                        end: None,
                        location,
                    });
                }
            }
        }

        cache.sort_by_key(|entry| entry.start);
        Self::dedupe_same_address_entries(cache)
    }

    fn dedupe_same_address_entries(
        entries: Vec<CachedLineEntry>,
    ) -> Result<Vec<CachedLineEntry>, gimli::Error> {
        let mut deduped: Vec<CachedLineEntry> = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(last) = deduped.last_mut() {
                if last.start == entry.start {
                    *last = entry;
                    continue;
                }
            }
            deduped.push(entry);
        }
        Ok(deduped)
    }

    fn attr_value_to_string<R>(
        dwarf: &Dwarf<R>,
        unit: &gimli::Unit<R>,
        value: gimli::AttributeValue<R>,
    ) -> Option<String>
    where
        R: Reader,
    {
        let raw = dwarf.attr_string(unit, value).ok()?;
        let bytes = raw.to_slice().ok()?;
        Some(String::from_utf8_lossy(bytes.as_ref()).into_owned())
    }

    pub fn map_wasm_offset_to_source(&self, wasm_offset: u64) -> Option<SourceLocation> {
        self.map_wasm_offset_to_source_for_contract(None, wasm_offset)
    }

    pub fn map_wasm_offset_to_source_for_contract(
        &self,
        contract_id: Option<&str>,
        wasm_offset: u64,
    ) -> Option<SourceLocation> {
        let symbols = self.select_contract_symbols(contract_id)?;
        if !symbols.has_symbols || symbols.line_cache.is_empty() {
            return None;
        }

        let idx = match symbols
            .line_cache
            .binary_search_by_key(&wasm_offset, |entry| entry.start)
        {
            Ok(index) => index,
            Err(0) => return None,
            Err(index) => index.saturating_sub(1),
        };

        let entry = symbols.line_cache.get(idx)?;
        if let Some(end) = entry.end {
            if wasm_offset >= end {
                return None;
            }
        }

        let mut location = entry.location.clone();

        // Add GitHub link if available
        if let Some(ref git_repo) = symbols.git_repo {
            location.github_link = git_repo.generate_file_link(&location.file, location.line);
        }

        Some(location)
    }

    pub fn map_frame_to_source(&self, frame: &StackFrame) -> Option<SourceLocation> {
        let offset = frame.wasm_offset?;
        self.map_wasm_offset_to_source_for_contract(frame.module.as_deref(), offset)
    }

    pub fn map_stack_trace_to_source(&self, frames: &[StackFrame]) -> Option<SourceLocation> {
        frames
            .iter()
            .find_map(|frame| self.map_frame_to_source(frame))
    }

    #[allow(dead_code)]
    pub fn create_source_location(
        &self,
        file: String,
        line: u32,
        column: Option<u32>,
    ) -> SourceLocation {
        let github_link = self
            .select_contract_symbols(None)
            .and_then(|symbols| symbols.git_repo.as_ref())
            .and_then(|repo| repo.generate_file_link(&file, line));

        SourceLocation {
            file,
            line,
            column,
            column_end: None,
            github_link,
        }
    }

    pub fn has_debug_symbols(&self) -> bool {
        self.has_debug_symbols_for_contract(None)
    }

    pub fn has_any_debug_symbols(&self) -> bool {
        self.contracts.values().any(|symbols| symbols.has_symbols)
    }

    pub fn has_debug_symbols_for_contract(&self, contract_id: Option<&str>) -> bool {
        self.select_contract_symbols(contract_id)
            .map(|symbols| symbols.has_symbols)
            .unwrap_or(false)
    }

    fn select_contract_symbols(&self, contract_id: Option<&str>) -> Option<&ContractSymbols> {
        contract_id
            .and_then(|id| self.contracts.get(id))
            .or_else(|| self.contracts.get(ROOT_CONTRACT_KEY))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_map_cache::{SourceMapCache, SourceMapCacheEntry};
    use tempfile::TempDir;

    fn mapper_with_cache(entries: Vec<CachedLineEntry>) -> SourceMapper {
        let mut contracts = HashMap::new();
        contracts.insert(
            ROOT_CONTRACT_KEY.to_string(),
            ContractSymbols {
                has_symbols: true,
                line_cache: entries,
                git_repo: None,
            },
        );

        SourceMapper {
            contracts,
        }
    }

    #[test]
    fn test_source_mapper_without_symbols() {
        let wasm_bytes = vec![0x00, 0x61, 0x73, 0x6d];
        let mapper = SourceMapper::new(wasm_bytes);

        assert!(!mapper.has_debug_symbols());
        assert!(mapper.map_wasm_offset_to_source(0x1234).is_none());
    }

    #[test]
    fn test_new_with_options_no_cache_still_parses() {
        let wasm_bytes = vec![0x00, 0x61, 0x73, 0x6d];
        let mapper = SourceMapper::new_with_options(wasm_bytes, true);

        // Should still work — just re-parsed without cache
        assert!(!mapper.has_debug_symbols());
        assert!(mapper.map_wasm_offset_to_source(0x1234).is_none());
    }

    #[test]
    fn test_cached_lookup_uses_address_ranges() {
        let mapper = mapper_with_cache(vec![
            CachedLineEntry {
                start: 0x10,
                end: Some(0x20),
                location: SourceLocation {
                    file: "lib.rs".into(),
                    line: 10,
                    column: Some(1),
                    column_end: None,
                    github_link: None,
                },
            },
            CachedLineEntry {
                start: 0x20,
                end: None,
                location: SourceLocation {
                    file: "lib.rs".into(),
                    line: 20,
                    column: Some(2),
                    column_end: None,
                    github_link: None,
                },
            },
        ]);

        let loc = mapper.map_wasm_offset_to_source(0x18).expect("mapping");
        assert_eq!(loc.line, 10);
        assert_eq!(loc.column, Some(1));

        let loc = mapper.map_wasm_offset_to_source(0x25).expect("mapping");
        assert_eq!(loc.line, 20);
    }

    #[test]
    fn test_cached_lookup_respects_range_end() {
        let mapper = mapper_with_cache(vec![CachedLineEntry {
            start: 0x10,
            end: Some(0x20),
            location: SourceLocation {
                file: "mod.rs".into(),
                line: 7,
                column: None,
                column_end: None,
                github_link: None,
            },
        }]);

        assert!(mapper.map_wasm_offset_to_source(0x20).is_none());
    }

    #[test]
    fn test_multi_contract_lookup_prefers_frame_module() {
        let root_location = SourceLocation {
            file: "root.rs".into(),
            line: 10,
            column: Some(1),
            column_end: None,
            github_link: None,
        };
        let token_location = SourceLocation {
            file: "token.rs".into(),
            line: 42,
            column: Some(7),
            column_end: None,
            github_link: None,
        };

        let mut contracts = HashMap::new();
        contracts.insert(
            ROOT_CONTRACT_KEY.to_string(),
            ContractSymbols {
                has_symbols: true,
                line_cache: vec![CachedLineEntry {
                    start: 0x100,
                    end: Some(0x200),
                    location: root_location,
                }],
                git_repo: None,
            },
        );
        contracts.insert(
            "token".to_string(),
            ContractSymbols {
                has_symbols: true,
                line_cache: vec![CachedLineEntry {
                    start: 0x100,
                    end: Some(0x200),
                    location: token_location,
                }],
                git_repo: None,
            },
        );

        let mapper = SourceMapper { contracts };
        let frame = StackFrame {
            index: 0,
            func_index: Some(7),
            func_name: Some("token::transfer".into()),
            wasm_offset: Some(0x120),
            module: Some("token".into()),
        };

        let loc = mapper.map_frame_to_source(&frame).expect("frame should resolve");
        assert_eq!(loc.file, "token.rs");
        assert_eq!(loc.line, 42);
    }

    #[test]
    fn test_source_location_serialization() {
        let location = SourceLocation {
            file: "test.rs".to_string(),
            line: 42,
            column: Some(10),
            column_end: Some(15),
            github_link: None,
        };

        let json = serde_json::to_string(&location).unwrap();
        assert!(json.contains("test.rs"));
        assert!(json.contains("42"));
    }

    #[test]
    fn test_source_location_with_github_link() {
        let location = SourceLocation {
            file: "test.rs".to_string(),
            line: 42,
            column: Some(10),
            column_end: None,
            github_link: Some("https://github.com/user/repo/blob/abc123/test.rs#L42".to_string()),
        };

        let json = serde_json::to_string(&location).unwrap();
        assert!(json.contains("test.rs"));
        assert!(json.contains("42"));
        assert!(json.contains("github.com"));
    }

    #[test]
    fn test_source_mapper_with_cache() {
        let temp_dir = TempDir::new().unwrap();
        let wasm_bytes = vec![0x00, 0x61, 0x73, 0x6d];
        let wasm_hash = SourceMapCache::compute_wasm_hash(&wasm_bytes);

        {
            let mapper = SourceMapper::new_with_options(wasm_bytes.clone(), false);
            assert!(!mapper.has_debug_symbols());
            let result = mapper.map_wasm_offset_to_source(0x1234);
            assert!(result.is_none());
        }

        let cache = SourceMapCache::with_cache_dir(temp_dir.path().to_path_buf()).unwrap();
        let entries = cache.list_cached().unwrap();
        assert_eq!(entries.len(), 0);

        let mut mappings = std::collections::HashMap::new();
        mappings.insert(
            0x1234,
            SourceLocation {
                file: "test.rs".to_string(),
                line: 42,
                column: Some(10),
                column_end: None,
                github_link: None,
            },
        );

        let entry = SourceMapCacheEntry {
            wasm_hash: wasm_hash.clone(),
            has_symbols: true,
            mappings,
            created_at: 1234567890,
        };

        cache.store(entry).unwrap();

        let entries = cache.list_cached().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].wasm_hash, wasm_hash);
    }

    #[test]
    fn test_wasm_hash() {
        let wasm_bytes = vec![0x00, 0x61, 0x73, 0x6d];
        let hash = SourceMapCache::compute_wasm_hash(&wasm_bytes);
        assert_eq!(hash.len(), 64);
    }
}
