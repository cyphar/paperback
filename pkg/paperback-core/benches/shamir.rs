/*
 * paperback: paper backup generator suitable for long-term storage
 * Copyright (C) 2018-2022 Aleksa Sarai <cyphar@cyphar.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::time::Duration;

use paperback_core::shamir::Dealer;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use rand::{distributions::Standard, Rng};

fn benchmark_dealer_next_shard(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir Dealer::next_shard");
    for quorum_size in (10..=40).step_by(10) {
        let vec = rand::thread_rng()
            .sample_iter(Standard)
            .take(1 << 12)
            .collect::<Vec<u8>>();
        let dealer = Dealer::new(quorum_size, &vec);
        group.measurement_time(Duration::new(60, 0));
        group.throughput(Throughput::Bytes(vec.len() as u64));
        group.bench_with_input(format!("N={:03}", quorum_size), &dealer, |b, dealer| {
            b.iter(|| dealer.next_shard())
        });
    }
    group.finish()
}

fn benchmark_recover_secret(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir recover secret");
    for quorum_size in (5..=65).step_by(5) {
        let vec = rand::thread_rng()
            .sample_iter(Standard)
            .take(1 << 12)
            .collect::<Vec<u8>>();
        let dealer = Dealer::new(quorum_size, &vec);
        let shards = (0..quorum_size)
            .map(|_| dealer.next_shard())
            .collect::<Vec<_>>();
        group.throughput(Throughput::Bytes(vec.len() as u64));
        group.measurement_time(Duration::new(40 + quorum_size as u64, 0));
        group.bench_with_input(
            format!("Dealer::recover().secret() N={:03}", quorum_size),
            &shards,
            |b, shards| b.iter(|| black_box(Dealer::recover(shards).unwrap()).secret()),
        );
    }
    group.finish()
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(250);
    targets = benchmark_dealer_next_shard, benchmark_recover_secret
}
criterion_main!(benches);
