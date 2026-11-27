---
layout: post
title: Validation II
---

In my previous blog post [Validation](..//Validation/) I described
Bitcoin Core's validation architecture, and how validation work is split up
into different phases. I ended it with a description of its current
bottlenecks, and what I would like to see improved. Bitcoin Core is currently
validating one block at a time. A global lock (cs_main) is applied over most of
validation. This limits the amount of parallelism possible. In this article, I
propose some techniques (treating blocks as the fundamental validation unit,
creating non-blocking I/O interfaces, segregating coin lookups from validation
and UTXO set mutation) to overcome this and provide good parallelism, while
preserving Bitcoin Core's constraints for running on low end hardware and
supporting full block pruning.

### Parallel Block Acceptance

The Check* and Accept* level validation functions currently run under cs_main.
This seems fairly straightforward to improve. A block's internal cache flags,
currently boolean values protected by cs_main, can be made atomics. Contextual
information required for validation can be passed either by copy or immutable
reference. Changes to the block's validation level can be done incrementally by
taking cs_main only for a brief amount of time.

AcceptBlock is also responsible for writing blocks to disk. Doing I/O
operations under the global lock is very undesirable: On many systems this
filesystem operation will be much slower than doing the actual validation work
in these functions. This can be avoided by splitting the operation into three
steps: First claiming its on-disk position/target/slot under the lock, then
writing it out without the lock, and if the write is successful finally marking
it as stored in the block index with the lock held again.

### Parallel Block Connection

These fairly straightforward changes allow for parallel processing of blocks up
to the "Chain"-level validation functions. Recapping briefly what currently
happens next, the functions check if a new next best candidate block is
available, either passed in directly or available on disk, and then do the
actual bulk of validation work: Gathering coins from the UTXO set, checking
double spends and amounts, updating the UTXO set, and running scripts.
Especially reading coins from the multi-Gigabyte UTXO set, requiring a map
lookup or disk read for every entry, and updating the UTXO set take a lot of
time.

The current CoinsViewOverlay and CCoinsViewCache layering already take some
steps between reading coins from the underlying UTXO set, and mutating it. The
changes to the UTXO set a block writes are gathered during validation in the
overlay and only flushed to the complete set on success. This underlying idea
of dividing reading coins, running validation, and applying coin changes can be
leveraged to achieve parallel validation.

To fully validate a block all the coins it is spending need to be available.
This constraint can be used as an advantage. When a candidate block to extend
the chain becomes available, it can help processing the next candidate block as
fast as possible by immediately making available all its outputs in a separate
cache for the subsequent blocks. It then reads its coins from the full UTXO set
and any preceding blocks' output caches (in youngest to oldest order) and
proceed with script execution. This part of the code running actual transaction
validation, i.e. the bulk of `ConnectBlock`, requires no significant changes.
Since this is a read only operation, other blocks can do this in parallel as
long as all their preceding blocks made their outputs available.

A method to make these parallel reads from the in-memory UTXO set possible
without having to lock cs_main and changing Leveldb or its current schema,
could be sharding it in the following manner. Each shard owns a range of the
UTXO set based on the leading prefix of the outpoint bytes. This establishes a
total ordering and distributes work evenly under the assumption that outpoint
bytes / txids are somewhat uniform. Every shard is guarded under its own lock.
A sufficiently large number of shards ensures that conflicting reads are rare,
so blocks reading in parallel don't have to wait for each other. Dividing
shards based on the leading outpoint bytes also matches Leveldb's
lexicographical key order, which makes db batch writes during flushes faster.

Conversely to the previous constraint once a block has completed validation,
its coin spends and creations need to be applied to the UTXO set in block
height order. Once a block has completed validation it can prepare a batched
instruction for mutating the sharded UTXO set as well as provide the undo data.
These batched instructions can then be applied to the UTXO set in height order.
Since this mechanism has only tracked newly-created outputs so far, this is
where conflicting spends are detected. If there is a conflict, earlier spends
from that block can be rolled back with the block's undo data. On each batch of
UTXO set applications cs_main is locked again to ensure a consistent, atomic
view for external consumers. However they can be applied in parallel with the
reads by relying on the shard locks. This means that validation and preparation
work can continue happening while the UTXO set is being written to. There is
potential here for a further cut through and parallelism by batching these
changes by shard.

If an invalid block is detected, the mechanism for resolution is simply to drop
any descendant blocks being validated at the same time and mark them invalid
too. By the same ActivateBestChain mechanism as currently a new candidate block
can then be selected.

### Results

There is a small memory trade-off during parallel processing: It retains a few
more blocks in flight and an extra copy of its outputs during validation.
However, this can be (de-)tuned by setting the number of blocks that may be
validated at once. This approach is compatible with pruning and requires next
to no changes to code outside of validation.

After experimentally implementing these changes, the results are promising. On
my machine, a fairly beefy 32 vcore 64GB RAM workstation, a reindex-chainstate
to height 975'000 finished in ~9 minutes compared to ~130 minutes on current
master. Interestingly, adding a few more optimisations, such as better
allocators and batching cryptographic operations, allowed me to push
reindex-chainstate time to under 6 minutes, and a non-assumevalid (i.e. full
validating) reindex-chainstate run to finish in half an hour. A full ibd run
done on the same machine to simulate no network interference, seems to show a
speed-up of a similar magnitude, finishing in around 35 minutes. This fulfills
the goal of moving the performance bottleneck away from validation and towards
the network's supply of blocks.
