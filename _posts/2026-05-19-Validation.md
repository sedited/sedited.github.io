Block validation logic in Bitcoin Core is surprisingly complex. After more than
a decade of engineering towards improving performance, Bitcoin Core has
accumulated many caching layers, sub-steps, and optimizations before the node
even calls the script interpreter. In the following, I'll describe in broad
strokes what these are, first roughly describing what validation is done in
which order (often skipping over some exact details), then explaining why it
was implemented in the way it is and the tradeoffs involved. I skip over
optimizations that do not affect the architecture in a significant way, like
low-level CPU instructions. This is based on my own understanding, which may be
wrong, and is definitely biased.

When a Bitcoin Core node receives a block, the node eventually passes it to the
[ProcessNewBlock](https://github.com/bitcoin/bitcoin/blob/7802e578c3f1e9a5d9b57fb003349d0e032bb43b/src/validation.cpp#L4387)
function. This is the entry point to the block validation logic. The checks the
block runs through require increasingly more "stateful" information. These
"stateful" data structures include all the known block headers and their
tree-like structure (tree-like because they may include stale forks - aka the
block tree), the currently best known chain of blocks, the UTXO set, and
several caching data structures.

The first family of validation functions is the "Check\*"-level functions. These
validate, among other things, the proof of work, the merkle root, size limits,
and a few other sanity checks to ensure the block is structurally sound. Even
though these checks are fairly cheap, a block caches internally whether it has
passed through these checks before, and if so, skips them.

The next group is the "Accept\*"-level functions. These interact with the block
tree, a structure where each block has a pointer to its parent, allowing
traversal back to genesis. It may include forks, forming a tree with a long
stem and short branches. As a subcategory, they also include the
"ContextualCheck\*"-level functions. The "ContextualCheck\*" functions don't
just involve checking that the previous block is already in the block tree and
that the timestamp is correct, but also enforce some rules around soft forks,
such as checking the block's version and whether the witness data is correctly
serialized. Once a block has passed these checks, it is added to the block tree
and written to disk. Crucially, this means a block that passed through these
checks, but is later found invalid, for example by an invalid script in one of
its transactions, is nevertheless persisted on disk. To avoid an attacker
filling the disk, single blocks below a certain cumulative proof of work
threshold are rejected.

Lastly, the block passes through the "Chain"-level validation functions. These
interact with two data structures: a vector of block tree entries from genesis
to the currently best known block for fast, height-indexed access referred to
as `CChain`, and the UTXO set (`CCoinsViewCache`), fundamentally a mapping from
a transaction out point to its corresponding transaction output (its `Coin`).
This provides and unifies both a "view" into the UTXO set persisted on disk,
and a "cache" for previously retrieved coins and coins that are spent within
the same block.

If the block extends the chain, the node retrieves the coins that are spent by
the block's transactions from the `CCoinsViewCache`. This retrieval checks that
all required coins exist and that there are no double spends. The coins are
also used to check that the transactions' input and output amounts balance.
Then the script interpreter is invoked for every input and its coin of every
transaction in the block. If these checks pass, new coins are added to the
cache. All the outputs that are spent by the block are added to a separate data
structure (`CBlockUndo`) and persisted to disk. This means that after
validation, every block persisted on disk also has a corresponding `CBlockUndo`
containing all the outputs the block has spent. This "undo" data is used during
a re-org: The coins spent by blocks no longer part of the chain are added back
to the `CCoinsViewCache`. Finally, the block is marked as valid and added to
the `CChain`.

The main design goal driving this architecture is allowing for
"[ultra-prune](https://github.com/bitcoin/bitcoin/pull/1677)": The node can
reduce its on-disk resource usage to the UTXO set plus a threshold buffer of
blocks to allow for re-orgs. Currently, pruned storage sits at around 18GB
versus 800GB for a fully archival node. Blocks beyond the threshold buffer can
be continuously deleted, even during initial blockchain download, freeing up
disk space and keeping disk consumption more or less constant. This means that
the UTXO set acts as a state accumulator for validation. Deleting the blocks
from disk is made easier by not having a complex data schema.

There are two main performance bottlenecks during block validation: evaluating
all the scripts (including their embedded signatures) and interacting with the
UTXO set. Both sit in the "Chain"-level of validation functions, which makes
these later validation steps the most expensive. Evaluating many signatures
requires significant computation and the size of the UTXO set (around 10GB)
makes interactions expensive.

Script validation speedups mostly come from improvements to the signature
verification code, both in `libsecp256k1` and the code for producing signature
message hashes. A block's transactions' scripts are also evaluated in parallel
using multiple CPU cores (`CCheckQueueControl`). Script validation is currently
the only validation step happening in parallel.

Historically, around 80% of spent coins are spent within a day of being created
([Liu et al.](https://pmc.ncbi.nlm.nih.gov/articles/PMC8989952/figure/Fig3/)).
This allows for an efficient caching strategy: By retaining the latest coins in
memory through the`CCoinsViewCache`, a cut-through optimization is achieved
that avoids reading and writing the short-lived coins to disk. Adding, reading,
and removing these coins happens entirely in memory, without any on-disk
interaction.

To maximise time spent in validation routines as opposed to having to wait on
blocks to arrive from peers, blocks can be processed out-of-order, allowing for
a constant feed of incoming blocks from peers to be processed. If an
out-of-order block has passed "Accept\*"-level validation, the "Chain"-level
routines will skip validation and just return early. Once the block's ancestors
have been added to the chain and it becomes a candidate for the best chain, it
is read from disk and then undergoes coin and script evaluation.

Before downloading full blocks, a node first syncs the best currently known
chain of block headers. Block headers are small (80 bytes each), making this
much faster compared to synchronizing blocks. The node validates these headers
through the `CheckBlockHeader`, `ContextualCheckBlockHeader`, and
`AcceptBlockHeader` functions, and adds them to the block tree. Once the
headers are synced, the node then begins requesting full blocks from peers
guided by this header chain.

Bitcoin Core also optimizes block relay and serving speed. Serving blocks
quickly makes other peer's IBD faster. Timely Block relay is a significant
factor in dictating miners' margin. `AcceptBlock` saves blocks to disk in their
full network serialization format. This allows a node to respond to a `GETDATA`
request without any (de-)serialization overhead. The node also immediately
relays blocks upon passing the "Accept\*"-level checks, before the expensive
script and coin validation steps. This means a node may be relaying blocks with
invalid transactions, though this is again mitigated by already having checked
that the proof of work is over a certain threshold.

Mempool transaction validation provides further optimizations that speed up
block validation after initial synchronization. Validating transaction scripts
for the mempool populates two caches: the signature and the script cache. This
involves running policy checks, meaning the rules are stricter than during
block-level validation. On this check, successfully validated signatures are
added to the signature cache, keyed by the hash of the signature data. The
scripts are then checked again, but with consensus-level rules applied. On
success, they get added to the script cache, keyed by transaction data and the
exact rules the scripts were evaluated under. This second round of validation
is cheaper, since the signatures are already cached as valid and may be skipped
during validation. Once the transaction is included in a block and its scripts
are validated, the script cache is consulted, and some script evaluations may
be skipped.

Bitcoin Core ships the default-on "assumevalid" feature, which skips script
validation for all historical blocks before a certain target block. The feature
introduces an additional trust assumption that a sufficiently buried target
block would have been rejected by majority hashrate if it had invalid scripts.
This is not a "checkpoint": it only skips script verification for blocks
building towards the target block. The target block is set by the Bitcoin Core
developers at release time, but users may override it. Coin-level checks are
still run, meaning users of this feature still validate all "Check\*"- and
"Accept\*"-level checks, and ensure that no coins are double-spent. For
platforms that lack processing power, like small system-on-a-chip computers,
this means a significant reduction in synchronization time.

The bulk of validation happens sequentially, one block at a time. The UTXO set
is atomically updated block-by-block. A future optimization allows for parallel
retrieval of coins from disk ([Bitcoin Core PR
#35295](https://github.com/bitcoin/bitcoin/pull/35295)), which alleviates this
bottleneck. This essentially pre-warms the cache of the `CCoinsViewCache`.
Still, no other validation work happens in the meantime, and the node is
blocked from making progress on other tasks.

A single mutex, `cs_main`, protects the validation caches, the UTXO set, and
the block tree. This means that no retrieval or mutation of any of these data
structures can happen in parallel. Breaking up `cs_main` and giving each data
structure its own mutex, does at least open up the possibility of racing the
various validation checks with each other. I would like to see more engineering
happening towards both reducing `cs_main`'s responsibility and parallelizing
more validation tasks.

Making block validation speed dependent on historical behaviour may have
downsides. During periods when a lot of non-standard transactions are being
mined, script validation gains no benefit from the script cache. If there is a
change in average coin lifetimes, like during a dust spam attack, the
cut-through the coins cache provides becomes less effective. In Bitcoin's
history such phases have been brief, and since the architectural cost here is
mostly code complexity as opposed to a fundamental limitation, these
optimizations are well worth it.

Writing fully serialized blocks to disk rather than persisting a fully
relational model means Bitcoin Core must do more work when making its data
available to wallets or block explorers through one of its interfaces. Bitcoin
Core uses optional indexes to index and expose some of this serialized data.
Clients can also implement their own indexing logic, for example to map
addresses to transactions.

Judging these tradeoffs is difficult. Based on the hardware and network
connection, validation might already be bottlenecked by the CPU, disk IO, or
network speed. Users also have different priorities. For miners, fast
validation and block relay after initial synchronization could dictate their
margins. Wallet users care most about not having to wait for blockchain
synchronization and getting rich data from their node. Others might depend on
pruning, since they lack the required disk space. It is unclear to me if a
single implementation can excel on all these fronts, or whether there are some
fundamental tradeoffs involved. Bitcoin Core should try to exploit available
hardware resources to their fullest extent. For most configurations, this
should mean moving the bottleneck further away from the CPU and disk and
towards network bandwidth.
