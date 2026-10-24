from flask import Flask, render_template, request, jsonify
import random

from simulation import (
    run_simulation, ID_BITS, MAX_CONNECTIONS, MAX_PER_SUBNET,
    NEW_PEER_CAP_RATIO, TRUST_MATURE_ROUNDS, NUM_SUBNETS,
)

app = Flask(__name__)

PARAMS = {
    "id_bits": ID_BITS,
    "max_connections": MAX_CONNECTIONS,
    "max_per_subnet": MAX_PER_SUBNET,
    "new_peer_cap_ratio": NEW_PEER_CAP_RATIO,
    "trust_mature_rounds": TRUST_MATURE_ROUNDS,
    "num_subnets": NUM_SUBNETS,
}


@app.route("/")
def home():
    return render_template("home.html", params=PARAMS, active_page="home")


@app.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html", params=PARAMS, active_page="how")


@app.route("/example")
def example_page():
    return render_template("example.html", params=PARAMS, active_page="example")


@app.route("/simulate")
def simulate_page():
    defaults = {
        "num_honest": 60,
        "num_attackers": 15,
        "rounds": 8,
        "attacker_subnet_span": 3,
    }
    return render_template("simulate.html", defaults=defaults, params=PARAMS, active_page="sim")


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    data = request.get_json(force=True) or {}

    try:
        num_honest = int(data.get("num_honest", 60))
        num_attackers = int(data.get("num_attackers", 15))
        rounds = int(data.get("rounds", 8))
        attacker_subnet_span = int(data.get("attacker_subnet_span", 3))
        seed = data.get("seed")
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid input types"}), 400

    # sane bounds so the UI stays responsive and the graph stays readable
    num_honest = max(1, min(num_honest, 200))
    num_attackers = max(0, min(num_attackers, 100))
    rounds = max(1, min(rounds, 15))
    attacker_subnet_span = max(1, min(attacker_subnet_span, NUM_SUBNETS))

    if seed is not None:
        try:
            random.seed(int(seed))
        except (TypeError, ValueError):
            pass

    result = run_simulation(
        num_honest=num_honest,
        num_attackers=num_attackers,
        rounds=rounds,
        attacker_subnet_span=attacker_subnet_span,
    )

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
