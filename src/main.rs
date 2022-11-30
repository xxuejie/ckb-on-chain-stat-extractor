use chrono::prelude::{DateTime, Utc};
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{
    BlockNumber, CellDep, CellOutput, DepType, Either, JsonBytes, OutPoint, TransactionView,
};
use ckb_mock_tx_types::{
    MockResourceLoader, MockTransaction, ReprMockCellDep, ReprMockInfo, ReprMockInput,
    ReprMockTransaction, Resource,
};
use ckb_script::{ScriptGroupType, TransactionScriptsVerifier};
use ckb_sdk::CkbRpcClient;
use ckb_types::{
    bytes::Bytes,
    core::{self, cell::resolve_transaction},
    packed,
    prelude::*,
    H256,
};
use clap::{arg, command, value_parser};
use lazy_static::lazy_static;
use lru::LruCache;
use serde::Serialize;
use std::collections::HashSet;
use std::fs::File;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    let matches = command!()
        .arg(
            arg!(--from <VALUE>)
                .required(true)
                .value_parser(value_parser!(u64)),
        )
        .arg(
            arg!(--to <VALUE>)
                .required(true)
                .value_parser(value_parser!(u64)),
        )
        .arg(
            arg!(--"vm-sample-times" <VALUE>)
                .value_parser(value_parser!(u8))
                .default_value("5"),
        )
        .arg(arg!(--rpc <VALUE>).default_value("http://127.0.0.1:8114"))
        .arg(arg!(--output <VALUE>).default_value("output.csv"))
        .get_matches();

    let from_block = *matches.get_one::<u64>("from").expect("required");
    let to_block = *matches.get_one::<u64>("to").expect("required");
    let vm_sample_times = *matches.get_one::<u8>("vm-sample-times").expect("required");
    let rpc = matches.get_one::<String>("rpc").expect("rpc");
    let output = matches.get_one::<String>("output").expect("output");

    let mut client = CkbRpcClient::new(rpc);
    let mut writer = csv::Writer::from_writer(File::create(&output).expect("create file"));

    for i in from_block..to_block {
        if (i - from_block) % 1000 == 0 {
            println!("Processing block {}", i);
        }

        let block = client
            .get_block_by_number(BlockNumber::from(i))
            .expect("rpc")
            .expect(&format!("block {} missing", i));

        let t: DateTime<Utc> = UNIX_EPOCH
            .checked_add(Duration::from_millis(block.header.inner.timestamp.value()))
            .expect("timestamp")
            .into();

        let mut offset = 0;
        if !block.transactions.is_empty() {
            let first_tx: packed::Transaction = block.transactions[0].inner.clone().into();
            if first_tx.is_cellbase() {
                offset = 1;
            }
        }

        for j in offset..block.transactions.len() {
            let tx = &block.transactions[j];
            let mock_tx = fill_transaction(tx, &mut client);
            let verifier_resource =
                Resource::from_both(&mock_tx, DummyResourceLoader {}).expect("create resource");
            let resolved_tx = resolve_transaction(
                mock_tx.core_transaction(),
                &mut HashSet::new(),
                &verifier_resource,
                &verifier_resource,
            )
            .expect("resolve");
            let verifier = TransactionScriptsVerifier::new(&resolved_tx, &verifier_resource);

            for (script_hash, group) in verifier.groups() {
                let mut total_runtime = Duration::default();
                let cycle = {
                    let a = SystemTime::now();
                    let cycle = verifier
                        .verify_single(group.group_type, &script_hash, u64::max_value())
                        .expect("run");
                    let b = SystemTime::now();
                    let d = b.duration_since(a).expect("clock goes backwards");
                    total_runtime = total_runtime.checked_add(d).expect("time overflow!");
                    cycle
                };

                for _ in 1..vm_sample_times {
                    let a = SystemTime::now();
                    let sample_cycle = verifier
                        .verify_single(group.group_type, &script_hash, u64::max_value())
                        .expect("run");
                    let b = SystemTime::now();
                    assert_eq!(sample_cycle, cycle);
                    let d = b.duration_since(a).expect("clock goes backwards");
                    total_runtime = total_runtime.checked_add(d).expect("time overflow!");
                }
                let runtime_nanoseconds = total_runtime.as_nanos() / vm_sample_times as u128;

                let script_data_hash = match verifier.extract_script(&group.script) {
                    Ok(data) => Some(blake2b_256(data).into()),
                    Err(_) => None,
                };

                writer
                    .serialize(Record {
                        tx_hash: tx.hash.clone(),
                        script_group_type: group.group_type,
                        input_indices: group
                            .input_indices
                            .iter()
                            .map(|i| format!("{}", i))
                            .collect::<Vec<String>>()
                            .join(";"),
                        output_indices: group
                            .output_indices
                            .iter()
                            .map(|i| format!("{}", i))
                            .collect::<Vec<String>>()
                            .join(";"),
                        cycle,
                        runtime_nanoseconds,
                        script_code_hash: group.script.code_hash().unpack(),
                        script_hash_type: group.script.hash_type().as_slice()[0],
                        script_data_hash,
                        block_number: block.header.inner.number.value(),
                        block_hash: block.header.hash.clone(),
                        block_timestamp: t.to_rfc3339(),
                    })
                    .expect("write csv line");
            }
        }
    }

    writer.flush().expect("flush");
}

#[derive(Debug, Serialize)]
struct Record {
    tx_hash: H256,
    script_group_type: ScriptGroupType,
    input_indices: String,
    output_indices: String,
    cycle: u64,
    runtime_nanoseconds: u128,
    script_code_hash: H256,
    script_hash_type: u8,
    script_data_hash: Option<H256>,
    block_number: u64,
    block_hash: H256,
    block_timestamp: String,
}

fn fill_transaction<'a>(tx: &TransactionView, client: &mut CkbRpcClient) -> MockTransaction {
    let inputs = tx
        .inner
        .inputs
        .iter()
        .map(|input| {
            let (output, data, header) = resolve_out_point(&input.previous_output, client);

            ReprMockInput {
                input: input.clone(),
                output,
                data,
                header,
            }
        })
        .collect();

    let header_deps = tx
        .inner
        .header_deps
        .iter()
        .map(|header_hash| {
            client
                .get_header(header_hash.clone())
                .expect("rpc")
                .expect(&format!("header {:x} missing", header_hash))
        })
        .collect();

    let mut cell_deps = Vec::new();
    for cell_dep in &tx.inner.cell_deps {
        cell_deps.extend(resolve_cell_dep(&cell_dep, client));
    }

    let mock_info = ReprMockInfo {
        inputs,
        cell_deps,
        header_deps,
    };

    let mock_tx = ReprMockTransaction {
        mock_info,
        tx: tx.inner.clone(),
    };

    mock_tx.into()
}

fn resolve_cell_dep(cell_dep: &CellDep, client: &mut CkbRpcClient) -> Vec<ReprMockCellDep> {
    let mut deps = Vec::new();
    let (output, data, header) = resolve_out_point(&cell_dep.out_point, client);
    deps.push(ReprMockCellDep {
        cell_dep: cell_dep.clone(),
        output,
        data: data.clone(),
        header,
    });
    if cell_dep.dep_type == DepType::DepGroup {
        let vec = packed::OutPointVec::from_slice(data.as_bytes()).expect("parsing OutPointVec");
        for o in vec {
            let (output, data, header) = resolve_out_point(&o.clone().into(), client);
            deps.push(ReprMockCellDep {
                cell_dep: CellDep {
                    out_point: o.into(),
                    dep_type: DepType::Code,
                },
                output,
                data,
                header,
            });
        }
    }
    deps
}

fn resolve_out_point(
    out_point: &OutPoint,
    client: &mut CkbRpcClient,
) -> (CellOutput, JsonBytes, Option<H256>) {
    let key: packed::OutPoint = out_point.clone().into();

    {
        if let Some(result) = CACHE.lock().expect("lock").get(&key).cloned() {
            return result;
        }
    }

    let tx_with_status = client
        .get_transaction(out_point.tx_hash.clone())
        .expect("rpc")
        .expect(&format!("tx {:x} missing", out_point.tx_hash));

    let tx: TransactionView = {
        let tx = tx_with_status
            .transaction
            .expect(&format!("tx {:x} missing", out_point.tx_hash));
        match tx.inner {
            Either::Left(tx) => tx,
            Either::Right(molecule_tx) => {
                packed::TransactionView::from_slice(molecule_tx.as_bytes())
                    .expect("molecule parsing")
                    .unpack()
                    .into()
            }
        }
    };
    let cell_output = tx.inner.outputs[out_point.index.value() as usize].clone();
    let data = tx.inner.outputs_data[out_point.index.value() as usize].clone();
    let header_hash = tx_with_status.tx_status.block_hash.clone();

    {
        CACHE.lock().expect("lock").push(
            key,
            (cell_output.clone(), data.clone(), header_hash.clone()),
        );
    }

    (cell_output, data, header_hash)
}

lazy_static! {
    static ref CACHE: Mutex<LruCache<packed::OutPoint, (CellOutput, JsonBytes, Option<H256>)>> =
        Mutex::new(LruCache::new(NonZeroUsize::new(1000).expect("non zero")));
}

struct DummyResourceLoader {}

impl MockResourceLoader for DummyResourceLoader {
    fn get_header(&mut self, hash: H256) -> Result<Option<core::HeaderView>, String> {
        return Err(format!("Header {:x} is missing!", hash));
    }

    fn get_live_cell(
        &mut self,
        out_point: packed::OutPoint,
    ) -> Result<Option<(packed::CellOutput, Bytes, Option<packed::Byte32>)>, String> {
        return Err(format!("Cell: {:?} is missing!", out_point));
    }
}
