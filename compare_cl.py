import argparse
import proof_size_estimate

"""
Size Comparison for Consensus Layer Attestations
using Falcon Signatures

Key difference from the execution layer (compare.py):
Validator public keys are already stored in the beacon state.
The verifier looks them up by validator index (~4 bytes), so
there is no per-attestation public key transmission cost.
"""

# =========================
# Parameters (in bytes)
# =========================

# Signature sizes (same Falcon-512 parameters as EL analysis)
s = 666 - 40       # standard signature size (pubkey known), excluding salt
s_tilde = 2 * s    # key-recovery signature size, excluding salt
r = 40              # salt/nonce size

# Key / address sizes
p = 897             # public key size (stored in beacon state, NOT transmitted)
idx = 4             # validator index size (uint32, negligible but included)

# Consensus layer context
ATTESTATIONS_PER_SLOT = 31_250  # ~1M validators / 32 slots

parser = argparse.ArgumentParser(description="CL storage cost estimation for Falcon signatures")
parser.add_argument(
    "-N", "--num-attestations",
    type=int,
    default=1024,
    help="Number of attestations (default: 1024)"
)
parser.add_argument(
    "--plot",
    action="store_true",
    help="Plot comparison graph"
)

args = parser.parse_args()
N = args.num_attestations


def aggregated_signature_size(N):
    """
    Aggregated signature size a_N (excluding salts).
    Uses LaBRADOR proof size estimates (optimistic lower bound).
    """
    proof_size_bits = proof_size_estimate.search(
        N, 15,
        proof_size_estimate.FALCON_64_128(),
        proof_size_estimate.CHAL_2_SPLIT_64_128(),
        8, False
    )
    return proof_size_bits / 8


# =========================
# Size Calculations
# =========================

# CL Case 1: Key Recovery, No Aggregation
# Larger signature recovers pubkey from signature — wasteful in CL
# since pubkeys are already in the beacon state, but included for comparison.
cl_case1_total = N * (s_tilde + r)

# CL Case 2: Standard Falcon, No Aggregation
# Verifier looks up pubkey from beacon state by validator index.
# Only signature + salt + index needed per attestation.
cl_case2_total = N * (s + r + idx)

# CL Case 3: Standard Falcon, With Aggregation
# Individual signatures replaced by one aggregated proof.
# Per attestation: only salt + validator index.
a_N = aggregated_signature_size(N)
cl_case3_total = a_N + N * (r + idx)

# =========================
# Output
# =========================

print("Consensus Layer Size Comparison (in bytes)")
print("=" * 50)
print(f"Number of attestations (N): {N}")
print(f"(Current Ethereum: ~{ATTESTATIONS_PER_SLOT:,} attestations/slot)")
print()

print("CL Case 1: Key Recovery, No Aggregation")
print(f"  Per attestation: {s_tilde + r:,} bytes")
print(f"  Total: {cl_case1_total:,} bytes ({cl_case1_total/1024:.1f} KiB)")
print()

print("CL Case 2: Standard Falcon, No Aggregation")
print(f"  Per attestation: {s + r + idx:,} bytes")
print(f"  Total: {cl_case2_total:,} bytes ({cl_case2_total/1024:.1f} KiB)")
print()

print("CL Case 3: Standard Falcon, With Aggregation")
print(f"  Aggregated proof size: {a_N:,.0f} bytes ({a_N/1024:.1f} KiB)")
print(f"  Per attestation overhead: {r + idx} bytes (salt + index)")
print(f"  Total: {cl_case3_total:,.0f} bytes ({cl_case3_total/1024:.1f} KiB)")
print()

if cl_case2_total > 0:
    ratio = cl_case2_total / cl_case3_total
    print(f"Aggregation compression vs Case 2: {ratio:.1f}x")
if cl_case1_total > 0:
    ratio = cl_case1_total / cl_case3_total
    print(f"Aggregation compression vs Case 1: {ratio:.1f}x")

# =========================
# Plotting
# =========================

if args.plot:
    import matplotlib.pyplot as plt
    import numpy as np

    N_values = np.linspace(64, 1000, 25, dtype=int)
    N_values = np.unique(N_values)

    case1_values = []
    case2_values = []
    case3_values = []
    valid_N_values = []

    print("\nCalculating CL storage costs for plotting...")
    for i, n in enumerate(N_values):
        try:
            a_n = aggregated_signature_size(int(n))
            c1 = n * (s_tilde + r)
            c2 = n * (s + r + idx)
            c3 = a_n + n * (r + idx)

            case1_values.append(c1)
            case2_values.append(c2)
            case3_values.append(c3)
            valid_N_values.append(n)

            print(f"  [{i+1}/{len(N_values)}] N={n}: Case1={c1/1024:.0f} KiB, Case2={c2/1024:.0f} KiB, Case3={c3/1024:.0f} KiB")
        except Exception as e:
            print(f"  Skipping N={n}: {e}")

    case1_kib = np.array(case1_values) / 1024
    case2_kib = np.array(case2_values) / 1024
    case3_kib = np.array(case3_values) / 1024
    valid_N_values = np.array(valid_N_values)

    # Find intersection: Case 2 vs Case 3
    diff_23 = case2_kib - case3_kib
    sign_changes_23 = np.where(np.diff(np.sign(diff_23)))[0]
    intersection_23 = None
    if len(sign_changes_23) > 0:
        i = sign_changes_23[0]
        x1, x2 = valid_N_values[i], valid_N_values[i + 1]
        y1, y2 = diff_23[i], diff_23[i + 1]
        intersection_23 = x1 - y1 * (x2 - x1) / (y2 - y1)
        print(f"\nIntersection (Case 2 & Case 3): N ≈ {intersection_23:.0f}")

    # Find intersection: Case 1 vs Case 3
    diff_13 = case1_kib - case3_kib
    sign_changes_13 = np.where(np.diff(np.sign(diff_13)))[0]
    intersection_13 = None
    if len(sign_changes_13) > 0:
        i = sign_changes_13[0]
        x1, x2 = valid_N_values[i], valid_N_values[i + 1]
        y1, y2 = diff_13[i], diff_13[i + 1]
        intersection_13 = x1 - y1 * (x2 - x1) / (y2 - y1)
        print(f"Intersection (Case 1 & Case 3): N ≈ {intersection_13:.0f}")

    colors = ['#2E86AB', '#A23B72', '#F18F01']

    plt.figure(figsize=(10, 6))
    plt.plot(valid_N_values, case1_kib,
             label='Case 1: Key Recovery, No Aggregation',
             linewidth=2, color=colors[0], marker='o', markersize=6, markevery=1)
    plt.plot(valid_N_values, case2_kib,
             label='Case 2: Standard Falcon, No Aggregation',
             linewidth=2, color=colors[1], marker='^', markersize=6, markevery=1)
    plt.plot(valid_N_values, case3_kib,
             label='Case 3: Standard Falcon, With Aggregation',
             linewidth=2, color=colors[2], marker='s', markersize=6, markevery=1)

    if intersection_23 is not None:
        plt.axvline(x=intersection_23, color='gray', linestyle='--', linewidth=1.5, alpha=0.7)

    plt.xlabel('Number of Signatures (N)', fontsize=12)
    plt.ylabel('Size (KiB)', fontsize=12)
    plt.title('Size Comparison for Falcon Signatures (Consensus Layer)', fontsize=14)
    plt.legend(loc='upper left', fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    plt.savefig('cl_storage_comparison.png', dpi=150)
    print(f"\nPlot saved to cl_storage_comparison.png")
