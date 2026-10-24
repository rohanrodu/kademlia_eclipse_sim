# Eclipse Attack Simulator — TABSD Defense (v2)

A multi-page Flask app that teaches and demonstrates Kademlia-style eclipse
attacks and a custom defense, with an actual live network graph instead of
raw tables.

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

## Pages

- **Home (`/`)** — landing page: what this is, quick visual, feature highlights.
- **How It Works (`/how-it-works`)** — four visual explainers: XOR distance &
  buckets, the eclipse attack, the TABSD defense's three layers, and how to
  read the simulation graph.
- **Simulation (`/simulate`)** — configure the network, run it, then step
  through rounds on a live radial graph:
  - Every dot is a peer, positioned by distance from the victim (center) —
    closer dots are in lower Kademlia buckets.
  - Blue = honest, red = malicious. Selected/connected peers are larger with
    a white outline and a line to the victim (green = safe connection, red =
    malicious connection).
  - Toggle between "Random Selection" and "TABSD Defense" to compare who
    gets connected under each strategy, same round, same network.
  - Step with Prev/Next, or hit Play to auto-advance through rounds.
  - A trend chart below shows malicious-connection counts across all rounds
    for both strategies.

## Algorithm — TABSD (Trust-weighted Adaptive Bucket & Subnet Diversity)

Three independent defenses layered together (see `simulation.py`):

1. **XOR bucket diversity** — guarantees at least one connection per occupied
   Kademlia bucket (`bucket = floor(log2(victim_id XOR peer_id))`), so
   attacker IDs clustered near the victim can only dominate the low buckets.
2. **Subnet capping** — caps connections per simulated subnet
   (`MAX_PER_SUBNET`), independent of ID, targeting the real-world limit on
   how many actual machines an attacker controls.
3. **Trust-weighted, age-gated selection** — new peers are capped to a small
   fraction of slots per round (`NEW_PEER_CAP_RATIO`) and selection favors
   peers with a longer track record (`trust_score`), with a chance of
   eviction for malicious peers each round.

None of these are individually bulletproof, and TABSD isn't claimed to be
unconditionally unbreakable — the simulator lets you see, honestly, how much
harder it makes a successful eclipse compared to naive random selection.

## Files

```
app.py                     Flask routes + /api/simulate JSON endpoint
simulation.py               All algorithm logic (framework-independent)
templates/
  base.html                shared layout + navbar
  home.html                landing page
  how_it_works.html        visual explainers (hand-built SVG diagrams)
  simulate.html            simulation page structure
static/
  style.css                all styling
  simulate.js              fetch + canvas graph rendering + round stepper
```

## Tunable parameters (`simulation.py`)

- `ID_BITS`, `MAX_CONNECTIONS`
- `MAX_PER_SUBNET`, `NUM_SUBNETS`
- `NEW_PEER_CAP_RATIO`, `TRUST_MATURE_ROUNDS`

## API

`POST /api/simulate`
```json
{
  "num_honest": 60,
  "num_attackers": 15,
  "rounds": 8,
  "attacker_subnet_span": 3,
  "seed": 42
}
```
Returns victim ID, config, and per-round history including the **full**
network snapshot (for graphing) plus which peer keys were selected by each
strategy.
