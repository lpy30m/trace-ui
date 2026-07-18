use crate::query::call_tree::CallTree;
use crate::scanner::RegLastDef;
use memmap2::Mmap;
use std::sync::Arc;
use trace_parser::types::RegId;

use super::bitvec::{BitView, FlatBitVec};
use super::cache_format::{SectionReader, SectionWriter};
use super::deps::{DepsView, FlatDeps};
use super::line_index::{LineIndexArchive, LineIndexView};
use super::mem_access::{FlatMemAccess, MemAccessView};
use super::mem_last_def::{FlatMemLastDef, MemLastDefView};
use super::pair_split::{FlatPairSplit, PairSplitView};
use super::reg_checkpoints::{FlatRegCheckpoints, RegCheckpointsView};
use super::scan_view::ScanView;

pub const HEADER_LEN: usize = 64;

// ── Phase2Archive ────────────────────────────────────────────────────────────

pub struct Phase2Archive {
    pub mem_accesses: FlatMemAccess,
    pub reg_checkpoints: FlatRegCheckpoints,
    pub call_tree: CallTree,
}

impl Phase2Archive {
    /// Serialize to section-based binary format.
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        // MemAccess: sections 0-2
        w.write_slice(&self.mem_accesses.addrs); // 0
        w.write_slice(&self.mem_accesses.offsets); // 1
        w.write_slice(&self.mem_accesses.records); // 2
                                                   // RegCheckpoints: sections 3-5
        w.write_u32(self.reg_checkpoints.interval); // 3
        w.write_u32(self.reg_checkpoints.count); // 4
        w.write_slice(&self.reg_checkpoints.data); // 5
                                                   // CallTree: section 6 (bincode, eagerly deserialized on load)
        let ct_bytes = bincode::serialize(&self.call_tree).unwrap();
        w.write_bytes(&ct_bytes); // 6
        w.finish()
    }

    /// Reconstruct views from mmap'd section data.
    /// `data` = &mmap[HEADER_LEN..] (after 64-byte cache header)
    pub fn views_from_sections(data: &[u8]) -> Option<Phase2Views<'_>> {
        let r = SectionReader::new(data)?;
        if r.num_sections() < 7 {
            return None;
        }
        let addrs = r.slice(0)?;
        let offsets: &[u32] = r.slice(1)?;
        let records = r.slice(2)?;
        if offsets.len() != addrs.len().checked_add(1)?
            || offsets.first().copied() != Some(0)
            || !offsets.windows(2).all(|pair| pair[0] <= pair[1])
            || offsets.last().copied()? as usize != records.len()
        {
            return None;
        }
        let interval = r.u32_val(3)?;
        let count = r.u32_val(4)?;
        let checkpoint_data: &[u64] = r.slice(5)?;
        if interval == 0
            || checkpoint_data.len()
                != (count as usize).checked_mul(super::reg_checkpoints::REG_COUNT)?
        {
            return None;
        }
        let call_tree_bytes = r.bytes(6)?;
        bincode::deserialize::<CallTree>(call_tree_bytes).ok()?;
        Some(Phase2Views {
            mem_accesses: MemAccessView::from_raw(addrs, offsets, records),
            reg_checkpoints: RegCheckpointsView::from_raw(interval, count, checkpoint_data),
            call_tree_bytes,
        })
    }
}

pub struct Phase2Views<'a> {
    pub mem_accesses: MemAccessView<'a>,
    pub reg_checkpoints: RegCheckpointsView<'a>,
    pub call_tree_bytes: &'a [u8], // bincode bytes, deserialize on demand
}

// ── ScanArchive ──────────────────────────────────────────────────────────────

pub struct ScanArchive {
    pub deps: FlatDeps,
    pub mem_last_def: FlatMemLastDef,
    pub pair_split: FlatPairSplit,
    pub init_mem_loads: FlatBitVec,
    pub reg_last_def_inner: Vec<u32>, // [u32; 98] serialized as Vec
    pub line_count: u32,
    pub parsed_count: u32,
    pub mem_op_count: u32,
}

impl ScanArchive {
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        // FlatDeps: sections 0-7
        w.write_slice(&self.deps.chunk_start_lines); // 0
        w.write_slice(&self.deps.chunk_offsets_start); // 1
        w.write_slice(&self.deps.chunk_data_start); // 2
        w.write_slice(&self.deps.all_offsets); // 3
        w.write_slice(&self.deps.all_data); // 4
        w.write_slice(&self.deps.patch_lines); // 5
        w.write_slice(&self.deps.patch_offsets); // 6
        w.write_slice(&self.deps.patch_data); // 7
                                              // FlatMemLastDef: sections 8-10
        w.write_slice(&self.mem_last_def.addrs); // 8
        w.write_slice(&self.mem_last_def.lines); // 9
        w.write_slice(&self.mem_last_def.values); // 10
                                                  // FlatPairSplit: sections 11-13
        w.write_slice(&self.pair_split.keys); // 11
        w.write_slice(&self.pair_split.seg_offsets); // 12
        w.write_slice(&self.pair_split.data); // 13
                                              // FlatBitVec: sections 14-15
        w.write_slice(&self.init_mem_loads.data); // 14
        w.write_u32(self.init_mem_loads.len); // 15
                                              // Metadata: sections 16-19
        w.write_slice(&self.reg_last_def_inner); // 16
        w.write_u32(self.line_count); // 17
        w.write_u32(self.parsed_count); // 18
        w.write_u32(self.mem_op_count); // 19
        w.finish()
    }

    pub fn views_from_sections(data: &[u8]) -> Option<ScanViews<'_>> {
        let r = SectionReader::new(data)?;
        if r.num_sections() < 20 {
            return None;
        }
        let chunk_start_lines: &[u32] = r.slice(0)?;
        let chunk_offsets_start: &[u32] = r.slice(1)?;
        let chunk_data_start: &[u32] = r.slice(2)?;
        let all_offsets: &[u32] = r.slice(3)?;
        let all_data: &[u32] = r.slice(4)?;
        let patch_lines: &[u32] = r.slice(5)?;
        let patch_offsets: &[u32] = r.slice(6)?;
        let patch_data: &[u32] = r.slice(7)?;
        let mem_addrs: &[u64] = r.slice(8)?;
        let mem_lines: &[u32] = r.slice(9)?;
        let mem_values: &[u64] = r.slice(10)?;
        let pair_keys: &[u32] = r.slice(11)?;
        let pair_offsets: &[u32] = r.slice(12)?;
        let pair_data: &[u32] = r.slice(13)?;
        let bit_data: &[u8] = r.slice(14)?;
        let bit_len = r.u32_val(15)?;
        let reg_last_def_inner: &[u32] = r.slice(16)?;
        let line_count = r.u32_val(17)?;
        let parsed_count = r.u32_val(18)?;
        let mem_op_count = r.u32_val(19)?;

        if chunk_start_lines.len() != chunk_offsets_start.len()
            || chunk_start_lines.len() != chunk_data_start.len()
            || (!chunk_start_lines.is_empty() && chunk_start_lines[0] != 0)
            || !chunk_start_lines.windows(2).all(|pair| pair[0] < pair[1])
            || mem_addrs.len() != mem_lines.len()
            || mem_addrs.len() != mem_values.len()
            || pair_offsets.len() != pair_keys.len().checked_mul(3)?.checked_add(1)?
            || !pair_offsets.windows(2).all(|pair| pair[0] <= pair[1])
            || pair_offsets.last().copied().unwrap_or(0) as usize > pair_data.len()
            || bit_len as usize > bit_data.len().checked_mul(8)?
            || reg_last_def_inner.len() < RegId::COUNT
            || parsed_count > line_count
        {
            return None;
        }
        if patch_lines.is_empty() {
            if !patch_offsets.is_empty() && patch_offsets != [0] {
                return None;
            }
        } else if patch_offsets.len() != patch_lines.len().checked_add(1)?
            || !patch_offsets.windows(2).all(|pair| pair[0] <= pair[1])
            || patch_offsets.last().copied()? as usize > patch_data.len()
        {
            return None;
        }
        for index in 0..chunk_start_lines.len() {
            let start_line = chunk_start_lines[index] as usize;
            let end_line = chunk_start_lines
                .get(index + 1)
                .copied()
                .unwrap_or(line_count) as usize;
            let local_lines = end_line.checked_sub(start_line)?;
            let offsets_base = chunk_offsets_start[index] as usize;
            let offsets_end = offsets_base.checked_add(local_lines)?.checked_add(1)?;
            let offsets = all_offsets.get(offsets_base..offsets_end)?;
            if !offsets.windows(2).all(|pair| pair[0] <= pair[1]) {
                return None;
            }
            let data_end =
                (chunk_data_start[index] as usize).checked_add(offsets.last().copied()? as usize)?;
            if data_end > all_data.len() {
                return None;
            }
        }
        Some(ScanViews {
            deps: DepsView::from_raw(
                chunk_start_lines,
                chunk_offsets_start,
                chunk_data_start,
                all_offsets,
                all_data,
                patch_lines,
                patch_offsets,
                patch_data,
            ),
            mem_last_def: MemLastDefView::from_raw(mem_addrs, mem_lines, mem_values),
            pair_split: PairSplitView::from_raw(pair_keys, pair_offsets, pair_data),
            init_mem_loads: BitView::from_raw(bit_data, bit_len),
            reg_last_def_inner,
            line_count,
            parsed_count,
            mem_op_count,
        })
    }
}

#[allow(dead_code)]
pub struct ScanViews<'a> {
    pub deps: DepsView<'a>,
    pub mem_last_def: MemLastDefView<'a>,
    pub pair_split: PairSplitView<'a>,
    pub init_mem_loads: BitView<'a>,
    pub reg_last_def_inner: &'a [u32],
    pub line_count: u32,
    pub parsed_count: u32,
    pub mem_op_count: u32,
}

// ── LineIndexArchive sections ────────────────────────────────────────────────

impl LineIndexArchive {
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        w.write_slice(&self.sampled_offsets); // 0
        w.write_u32(self.total); // 1
        w.finish()
    }

    pub fn views_from_sections(data: &[u8]) -> Option<LineIndexView<'_>> {
        let r = SectionReader::new(data)?;
        if r.num_sections() < 2 {
            return None;
        }
        let sampled_offsets: &[u64] = r.slice(0)?;
        let total = r.u32_val(1)?;
        let required = if total == 0 {
            0
        } else {
            ((total - 1) / 256 + 1) as usize
        };
        if sampled_offsets.len() < required {
            return None;
        }
        Some(LineIndexView::from_raw(sampled_offsets, total))
    }
}

// ── CachedStore ──────────────────────────────────────────────────────────────

pub enum CachedStore<A> {
    Owned(A),
    Mapped(Arc<Mmap>),
}

// ── CachedStore<Phase2Archive> ───────────────────────────────────────────────

impl CachedStore<Phase2Archive> {
    pub fn mem_accesses_view(&self) -> MemAccessView<'_> {
        match self {
            Self::Owned(a) => a.mem_accesses.view(),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.mem_accesses
            }
        }
    }

    pub fn reg_checkpoints_view(&self) -> RegCheckpointsView<'_> {
        match self {
            Self::Owned(a) => a.reg_checkpoints.view(),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.reg_checkpoints
            }
        }
    }

    pub fn deserialize_call_tree(&self) -> CallTree {
        match self {
            Self::Owned(a) => a.call_tree.clone(),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                bincode::deserialize(views.call_tree_bytes)
                    .expect("failed to deserialize CallTree from cache")
            }
        }
    }
}

// ── CachedStore<ScanArchive> ─────────────────────────────────────────────────

impl CachedStore<ScanArchive> {
    pub fn deps_view(&self) -> DepsView<'_> {
        match self {
            Self::Owned(a) => a.deps.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.deps
            }
        }
    }

    pub fn mem_last_def_view(&self) -> MemLastDefView<'_> {
        match self {
            Self::Owned(a) => a.mem_last_def.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.mem_last_def
            }
        }
    }

    pub fn pair_split_view(&self) -> PairSplitView<'_> {
        match self {
            Self::Owned(a) => a.pair_split.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.pair_split
            }
        }
    }

    pub fn init_mem_loads_view(&self) -> BitView<'_> {
        match self {
            Self::Owned(a) => a.init_mem_loads.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.init_mem_loads
            }
        }
    }

    pub fn line_count(&self) -> u32 {
        match self {
            Self::Owned(a) => a.line_count,
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.line_count
            }
        }
    }

    pub fn reg_last_def_inner(&self) -> &[u32] {
        match self {
            Self::Owned(a) => &a.reg_last_def_inner,
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.reg_last_def_inner
            }
        }
    }

    pub fn deserialize_reg_last_def(&self) -> RegLastDef {
        let inner = self.reg_last_def_inner();
        let mut rld = RegLastDef::new();
        for (i, &v) in inner.iter().enumerate().take(RegId::COUNT) {
            if v != u32::MAX {
                rld.insert(RegId(i as u8), v);
            }
        }
        rld
    }

    pub fn scan_view(&self) -> ScanView<'_> {
        ScanView {
            deps: self.deps_view(),
            pair_split: self.pair_split_view(),
            line_count: self.line_count(),
        }
    }
}

// ── CachedStore<LineIndexArchive> ────────────────────────────────────────────

impl CachedStore<LineIndexArchive> {
    pub fn total_lines(&self) -> u32 {
        self.view().total_lines()
    }

    pub fn view(&self) -> LineIndexView<'_> {
        match self {
            Self::Owned(a) => a.view(),
            Self::Mapped(mmap) => {
                LineIndexArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase2_rejects_invalid_mem_access_csr() {
        let mut writer = SectionWriter::new();
        writer.write_slice(&[0x1000u64]);
        writer.write_slice(&[0u32]);
        writer.write_slice::<super::super::mem_access::FlatMemAccessRecord>(&[]);
        writer.write_u32(1000);
        writer.write_u32(0);
        writer.write_slice::<u64>(&[]);
        writer.write_bytes(&bincode::serialize(&CallTree { nodes: vec![] }).unwrap());
        let bytes = writer.finish();

        assert!(Phase2Archive::views_from_sections(&bytes).is_none());
    }

    #[test]
    fn line_index_rejects_missing_sample_offsets() {
        let mut writer = SectionWriter::new();
        writer.write_slice::<u64>(&[]);
        writer.write_u32(1);
        let bytes = writer.finish();

        assert!(LineIndexArchive::views_from_sections(&bytes).is_none());
    }
}
