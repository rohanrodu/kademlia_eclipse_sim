"""
simulation.py
-------------
Eclipse-attack simulation with a custom peer-selection defense:

    TABSD  ->  Trust-weighted Adaptive Bucket & Subnet Diversity

Inspired by Kademlia's XOR-bucket routing table, extended with two extra
defenses plain bucket diversity does not provide:

  1. SUBNET CAPPING
     Real eclipse attackers rarely control thousands of unique IP ranges,
     even if they can mint thousands of node IDs. Every simulated peer has
     a coarse "subnet", and connections are capped per subnet regardless
     of which XOR bucket the peer lands in.

  2. TRUST-WEIGHTED / AGE-GATED SELECTION
     Freshly-seen peers are capped to a small fraction of connection slots
     each round, and selection is weighted by an accumulated trust score
     (rounds survived). This defeats a single-shot flood, forcing an
     attacker to sustain presence over many rounds.

This module is UI-agnostic: `run_simulation()` returns a plain-dict
structure (JSON serialisable) including a FULL per-round network snapshot
(not just the selected peers) so a frontend can render an actual graph of
"who is near the victim" and "who got connected".
"""

import random
import math
from collections import defaultdict

# ----------------------------
# Configuration (tunable)
# ----------------------------

ID_BITS = 8
MAX_CONNECTIONS = 8
MAX_PER_SUBNET = 2             # cap connections coming from one simulated subnet
NEW_PEER_CAP_RATIO = 0.3       # max fraction of slots given to "unproven" peers per round
TRUST_MATURE_ROUNDS = 3        # rounds a peer must survive to count as "trusted"
NUM_SUBNETS = 16               # size of the simulated subnet space

_PEER_COUNTER = 0


# ----------------------------
# Peer
# ----------------------------

class Peer:
    __slots__ = ("key", "node_id", "subnet", "malicious", "joined_round", "trust_score")

    def __init__(self, node_id, subnet, malicious=False, joined_round=0):
        global _PEER_COUNTER
        _PEER_COUNTER += 1
        self.key = _PEER_COUNTER   # unique per-object identity. node_id space is
                                   # small and WILL collide -- that's part of the attack.
        self.node_id = node_id
        self.subnet = subnet
        self.malicious = malicious
        self.joined_round = joined_round
        self.trust_score = 0

    def age(self, current_round):
        return current_round - self.joined_round

    def is_trusted(self, current_round):
        return self.age(current_round) >= TRUST_MATURE_ROUNDS

    def to_dict(self, victim_id):
        return {
            "key": self.key,
            "id": self.node_id,
            "subnet": self.subnet,
            "malicious": self.malicious,
            "trust": self.trust_score,
            "bucket": bucket_index(victim_id, self.node_id),
        }

    def __repr__(self):
        tag = "M" if self.malicious else "H"
        return f"{tag}:{self.node_id}(sub{self.subnet})"


# ----------------------------
# XOR distance / Kademlia bucket index
# ----------------------------

def xor_distance(a, b):
    return a ^ b


def bucket_index(victim_id, peer_id):
    distance = xor_distance(victim_id, peer_id)
    if distance == 0:
        return None
    return int(math.log2(distance))


def build_buckets(victim_id, peers):
    buckets = defaultdict(list)
    for peer in peers:
        idx = bucket_index(victim_id, peer.node_id)
        if idx is not None:
            buckets[idx].append(peer)
    return buckets


# ----------------------------
# Baseline (vulnerable) selection
# ----------------------------

def vulnerable_selection(peers):
    """Plain uniform random sample -- no ID or subnet awareness at all."""
    k = min(MAX_CONNECTIONS, len(peers))
    return random.sample(peers, k)


# ----------------------------
# Weighted choice helper
# ----------------------------

def _weighted_choice(pool):
    weights = [p.trust_score + 1 for p in pool]  # +1 so score 0 still has a chance
    return random.choices(pool, weights=weights, k=1)[0]


# ----------------------------
# TABSD defense
# ----------------------------

def tabsd_selection(victim_id, peers, current_round):
    buckets = build_buckets(victim_id, peers)
    bucket_ids = list(buckets.keys())
    random.shuffle(bucket_ids)

    selected = []
    subnet_counts = defaultdict(int)
    max_new = max(1, math.floor(MAX_CONNECTIONS * NEW_PEER_CAP_RATIO))
    new_count = 0

    def eligible(candidates):
        return [p for p in candidates
                if p not in selected and subnet_counts[p.subnet] < MAX_PER_SUBNET]

    def try_pick(pool):
        nonlocal new_count
        if not pool:
            return None
        trusted_pool = [p for p in pool if p.is_trusted(current_round)]
        new_pool = [p for p in pool if not p.is_trusted(current_round)]

        if trusted_pool:
            choice = _weighted_choice(trusted_pool)
        elif new_pool and new_count < max_new:
            choice = _weighted_choice(new_pool)
        else:
            return None

        if not choice.is_trusted(current_round):
            new_count += 1
        selected.append(choice)
        subnet_counts[choice.subnet] += 1
        return choice

    # Pass 1: guarantee at least one peer per occupied bucket
    for b in bucket_ids:
        if len(selected) >= MAX_CONNECTIONS:
            break
        try_pick(eligible(buckets[b]))

    # Pass 2: fill remaining slots from the whole eligible population
    attempts = 0
    all_candidates = [p for bucket in buckets.values() for p in bucket]
    while len(selected) < MAX_CONNECTIONS and attempts < 500:
        attempts += 1
        pool = eligible(all_candidates)
        if not pool:
            break
        if try_pick(pool) is None and attempts > 250:
            pool = [p for p in all_candidates if p not in selected]
            if pool:
                choice = _weighted_choice(pool)
                selected.append(choice)
                subnet_counts[choice.subnet] += 1

    return selected


# ----------------------------
# Network generation
# ----------------------------

def create_honest_nodes(count, current_round=0):
    peers = []
    for _ in range(count):
        peers.append(Peer(
            node_id=random.randint(1, 2 ** ID_BITS - 1),
            subnet=random.randint(0, NUM_SUBNETS - 1),
            malicious=False,
            joined_round=random.randint(0, max(0, current_round - 1)) if current_round else 0,
        ))
    return peers


def create_attacker_nodes(victim_id, count, current_round=0, subnet_span=3):
    """Attacker mints many IDs close to the victim (classic eclipse strategy)
    but is limited in how many real subnets it actually controls."""
    peers = []
    controlled_subnets = random.sample(range(NUM_SUBNETS), min(subnet_span, NUM_SUBNETS))
    for _ in range(count):
        fake_id = victim_id ^ random.randint(1, 15)
        peers.append(Peer(
            node_id=fake_id,
            subnet=random.choice(controlled_subnets),
            malicious=True,
            joined_round=current_round,
        ))
    return peers


# ----------------------------
# Multi-round simulation
# ----------------------------

def run_simulation(num_honest, num_attackers, rounds, attacker_subnet_span=3, victim_id=None):
    if victim_id is None:
        victim_id = random.randint(1, 2 ** ID_BITS - 1)

    honest_pool = create_honest_nodes(num_honest, current_round=0)

    history = []
    all_peer_state = {p.key: p for p in honest_pool}

    for r in range(rounds):
        attackers = create_attacker_nodes(victim_id, num_attackers, current_round=r,
                                           subnet_span=attacker_subnet_span)
        for a in attackers:
            all_peer_state[a.key] = a

        network = list(all_peer_state.values())

        vulnerable_selected = vulnerable_selection(network)
        secure_selected = tabsd_selection(victim_id, network, current_round=r)

        # naive trust/eviction model:
        # - honest peers selected this round always gain trust
        # - malicious peers selected have a chance of being detected & evicted
        #   (trust reset, must rebuild reputation from scratch)
        for p in secure_selected:
            if p.malicious and random.random() < 0.4:
                p.trust_score = 0
                p.joined_round = r + 1
            else:
                p.trust_score += 1

        def summarize(selected):
            mal = sum(p.malicious for p in selected)
            return {
                "selected_keys": [p.key for p in selected],
                "total": len(selected),
                "malicious": mal,
                "eclipsed": mal > len(selected) / 2,
            }

        history.append({
            "round": r + 1,
            "network": [p.to_dict(victim_id) for p in network],
            "vulnerable": summarize(vulnerable_selected),
            "secure": summarize(secure_selected),
        })

    return {
        "victim_id": victim_id,
        "config": {
            "num_honest": num_honest,
            "num_attackers": num_attackers,
            "rounds": rounds,
            "max_connections": MAX_CONNECTIONS,
            "max_per_subnet": MAX_PER_SUBNET,
            "new_peer_cap_ratio": NEW_PEER_CAP_RATIO,
            "trust_mature_rounds": TRUST_MATURE_ROUNDS,
            "id_bits": ID_BITS,
        },
        "history": history,
    }


if __name__ == "__main__":
    result = run_simulation(num_honest=60, num_attackers=60, rounds=5)
    for rnd in result["history"]:
        v, s = rnd["vulnerable"], rnd["secure"]
        print(f"Round {rnd['round']:>2} | network={len(rnd['network']):>4} | "
              f"Random {v['malicious']}/{v['total']} {'ECLIPSED' if v['eclipsed'] else 'safe':>8} | "
              f"TABSD {s['malicious']}/{s['total']} {'ECLIPSED' if s['eclipsed'] else 'safe':>8}")
