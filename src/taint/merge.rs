// Cross-chunk merge and fixup logic

#![allow(dead_code)]

use rustc_hash::FxHashMap;

use crate::taint::parallel_types::{PartialUnresolvedLoad, UnresolvedLoad};
use crate::taint::scanner::RegLastDef;

/// Resolve a fully unresolved load using global state.
/// Determines pass-through exactly as single-threaded scan would.
pub fn resolve_unresolved_load(
    load: &UnresolvedLoad,
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    global_reg_last_def: &RegLastDef,
    patch_edges: &mut Vec<(u32, u32)>,
    init_corrections: &mut Vec<(u32, bool)>,
) {
    let mut all_same_store = true;
    let mut first_store_raw: Option<u32> = None;
    let mut store_val: Option<u64> = None;
    let mut has_init_mem = false;

    for offset in 0..load.width as u64 {
        if let Some(&(def_line, def_val)) = global_mem_last_def.get(&(load.addr + offset)) {
            patch_edges.push((load.line, def_line));
            match first_store_raw {
                None => {
                    first_store_raw = Some(def_line);
                    store_val = Some(def_val);
                }
                Some(first) if first != def_line => {
                    all_same_store = false;
                }
                _ => {}
            }
        } else {
            has_init_mem = true;
            all_same_store = false;
        }
    }

    // Pass-through check: exact same logic as scan_unified
    let is_pass_through = all_same_store
        && store_val.is_some()
        && load.load_value.is_some()
        && store_val.unwrap() == load.load_value.unwrap();

    if !is_pass_through {
        // Not pass-through → add register deps
        for r in &load.uses {
            if let Some(&def_line) = global_reg_last_def.get(r) {
                patch_edges.push((load.line, def_line));
            }
        }
    }

    // Correct init_mem_loads
    if !has_init_mem {
        init_corrections.push((load.line, false));
    }
}

/// Resolve partially unresolved loads — supplement missing mem deps.
/// Pass-through is already determined as false (mixed case). Reg deps already added.
pub fn resolve_partial_unresolved_loads(
    partials: &[PartialUnresolvedLoad],
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    patch_edges: &mut Vec<(u32, u32)>,
    init_corrections: &mut Vec<(u32, bool)>,
) {
    for partial in partials {
        let mut all_found = true;
        for &addr in &partial.missing_addrs {
            if let Some(&(def_line, _)) = global_mem_last_def.get(&addr) {
                patch_edges.push((partial.line, def_line));
            } else {
                all_found = false;
            }
        }
        if all_found {
            init_corrections.push((partial.line, false));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint::types::RegId;
    use smallvec::smallvec;

    #[test]
    fn test_resolve_load_passthrough() {
        let mut global_mem = FxHashMap::default();
        for i in 0..8u64 {
            global_mem.insert(0x8000 + i, (10u32, 0x42u64));
        }
        let load = UnresolvedLoad {
            line: 20,
            addr: 0x8000,
            width: 8,
            load_value: Some(0x42),
            uses: smallvec![RegId(1), RegId(2)],
        };
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(1), 5);
        global_reg.insert(RegId(2), 8);

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_unresolved_load(
            &load,
            &global_mem,
            &global_reg,
            &mut patch_edges,
            &mut init_corrections,
        );

        // Pass-through: only memory dep (one unique store line), no register deps
        assert!(patch_edges.iter().all(|&(from, _)| from == 20));
        assert!(patch_edges.iter().any(|&(_, to)| to == 10)); // mem dep
        assert!(!patch_edges.iter().any(|&(_, to)| to == 5)); // no reg dep x1
        assert!(!patch_edges.iter().any(|&(_, to)| to == 8)); // no reg dep x2
        assert_eq!(init_corrections, vec![(20, false)]);
    }

    #[test]
    fn test_resolve_load_not_passthrough_different_value() {
        let mut global_mem = FxHashMap::default();
        for i in 0..8u64 {
            global_mem.insert(0x8000 + i, (10u32, 0x99u64));
        }
        let load = UnresolvedLoad {
            line: 20,
            addr: 0x8000,
            width: 8,
            load_value: Some(0x42), // != 0x99
            uses: smallvec![RegId(1)],
        };
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(1), 5);

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_unresolved_load(
            &load,
            &global_mem,
            &global_reg,
            &mut patch_edges,
            &mut init_corrections,
        );

        assert!(patch_edges.iter().any(|&(_, to)| to == 10)); // mem dep
        assert!(patch_edges.iter().any(|&(_, to)| to == 5)); // reg dep
    }

    #[test]
    fn test_resolve_load_init_mem() {
        // No global store exists → truly initial memory
        let global_mem = FxHashMap::default();
        let load = UnresolvedLoad {
            line: 20,
            addr: 0x8000,
            width: 4,
            load_value: None,
            uses: smallvec![RegId(1)],
        };
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(1), 5);

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_unresolved_load(
            &load,
            &global_mem,
            &global_reg,
            &mut patch_edges,
            &mut init_corrections,
        );

        // No mem deps (no store found), but reg deps added (not pass-through)
        assert!(patch_edges.iter().any(|&(_, to)| to == 5));
        // init_mem_loads should NOT be corrected (it IS truly initial)
        assert!(init_corrections.is_empty());
    }

    #[test]
    fn test_resolve_partial_loads() {
        let mut global_mem = FxHashMap::default();
        global_mem.insert(0x8002u64, (15u32, 0u64));
        global_mem.insert(0x8003u64, (15u32, 0u64));

        let partials = vec![PartialUnresolvedLoad {
            line: 25,
            missing_addrs: smallvec![0x8002, 0x8003],
        }];

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_partial_unresolved_loads(
            &partials,
            &global_mem,
            &mut patch_edges,
            &mut init_corrections,
        );

        assert!(patch_edges.iter().any(|&(from, to)| from == 25 && to == 15));
        assert_eq!(init_corrections, vec![(25, false)]);
    }
}
