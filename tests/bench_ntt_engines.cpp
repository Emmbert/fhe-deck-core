// bench_ntt_engines.cpp
//
// Benchmarks NaiveNegacyclicMultiplicationEngine, PortableNTTEngine, and (if
// this build was configured with -DNTT_ENGINE=Hexl) IntelHexlNTTEngine
// side by side, on the real ring degrees and NTT-friendly moduli this
// project uses.
//
// Build (to include HEXL in the comparison; requires x86 + network access to
// fetch HEXL):
//   cmake -S . -B build -DNTT_ENGINE=Hexl -DINV_ENGINE=BUILDIN \
//         -DFFT_ENGINE=BUILDIN -DFFT_LONG_DOUBLE_ENGINE=BUILDIN \
//         -DUSE_CEREAL=FALSE -DUSE_TESTS=TRUE -DCMAKE_BUILD_TYPE=Release
//   cmake --build build -j
//   ./build/tests/bench_ntt_engines
//
// Build (portable-only, e.g. to sanity check on a non-x86 machine; skips the
// HEXL rows):
//   cmake -S . -B build -DNTT_ENGINE=BUILDIN -DINV_ENGINE=BUILDIN \
//         -DFFT_ENGINE=BUILDIN -DFFT_LONG_DOUBLE_ENGINE=BUILDIN \
//         -DUSE_CEREAL=FALSE -DUSE_TESTS=TRUE -DCMAKE_BUILD_TYPE=Release
//   cmake --build build -j
//   ./build/tests/bench_ntt_engines
//
// Note: NaiveNegacyclicMultiplicationEngine and PortableNTTEngine are always
// compiled into libfhe_deck regardless of NTT_ENGINE (only
// intel_hexl_engine.cpp is conditionally excluded), so both are always
// available here. Only the HEXL rows depend on which NTT_ENGINE this build
// was configured with.

#include "fhe_deck.h"
#include "math/naive_multiplication_engine.h"
#include "math/portable_ntt_engine.h"

#if defined(USE_IntelHexl)
#include "math/intel_hexl_engine.h"
#endif

#include <chrono>
#include <iostream>
#include <iomanip>
#include <memory>
#include <random>
#include <string>

using namespace FHEDeck;
using Clock = std::chrono::steady_clock;

static double ms_since(Clock::time_point start){
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

/// Times, for a single engine:
///   - forward+inverse NTT round trip (to_eval then to_coef) of one polynomial
///   - a full polynomial x polynomial multiplication (to_eval both operands,
///     mul in eval form, to_coef the result) -- the cost profile of a single
///     RLWE ciphertext x plaintext multiplication
/// averaged over `trials` repetitions, plus an "x264" total that approximates
/// (does not reproduce exactly) the repeated-multiplication cost of a client
/// eval-key-generation-sized workload (this project measured ~264 RLWE
/// encryptions for its real key-switching-key generation).
struct EngineBenchResult {
    std::string name;
    double round_trip_ms = 0.0;
    double mul_ms = 0.0;
    double x264_mul_ms = 0.0;
    bool x264_extrapolated = false; // true for Naive: too slow to run 264x directly
};

EngineBenchResult bench_engine(const std::string& name,
                                std::shared_ptr<PolynomialMultiplicationEngine> engine,
                                int32_t degree, int64_t modulus, int32_t trials,
                                bool extrapolate_x264){
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<int64_t> dist(0, modulus - 1);

    Polynomial a(degree, modulus);
    Polynomial b(degree, modulus);
    for(int32_t i = 0; i < degree; ++i){ a[i] = dist(rng); b[i] = dist(rng); }

    std::shared_ptr<PolynomialEvalForm> a_eval = engine->init_polynomial_eval_form();
    std::shared_ptr<PolynomialEvalForm> b_eval = engine->init_polynomial_eval_form();
    std::shared_ptr<PolynomialEvalForm> out_eval = engine->init_polynomial_eval_form();
    Polynomial out(degree, modulus);

    // Warm-up (avoids counting one-time allocator/cache effects in the
    // first measured iteration).
    engine->to_eval(*a_eval, a);
    engine->to_coef(out, *a_eval);

    EngineBenchResult result;
    result.name = name;
    result.x264_extrapolated = extrapolate_x264;

    // --- round trip: to_eval + to_coef -------------------------------------
    {
        auto start = Clock::now();
        for(int32_t t = 0; t < trials; ++t){
            engine->to_eval(*a_eval, a);
            engine->to_coef(out, *a_eval);
        }
        result.round_trip_ms = ms_since(start) / trials;
    }

    // --- full multiplication: to_eval(a), to_eval(b), mul, to_coef --------
    {
        auto start = Clock::now();
        for(int32_t t = 0; t < trials; ++t){
            engine->to_eval(*a_eval, a);
            engine->to_eval(*b_eval, b);
            engine->mul(*out_eval, *a_eval, *b_eval);
            engine->to_coef(out, *out_eval);
        }
        result.mul_ms = ms_since(start) / trials;
    }

    // --- x264 total ---------------------------------------------------------
    // Naive is too slow to actually run 264 times in a benchmark that also
    // covers n=4096, so its total is extrapolated from the measured per-op
    // mul time instead (accurate enough: naive's mul time has negligible
    // run-to-run variance). The NTT-based engines run the real 264
    // iterations since they're fast enough.
    constexpr int32_t kRepeats = 264;
    if(extrapolate_x264){
        result.x264_mul_ms = result.mul_ms * kRepeats;
    } else {
        auto start = Clock::now();
        for(int32_t t = 0; t < kRepeats; ++t){
            engine->to_eval(*a_eval, a);
            engine->to_eval(*b_eval, b);
            engine->mul(*out_eval, *a_eval, *b_eval);
            engine->to_coef(out, *out_eval);
        }
        result.x264_mul_ms = ms_since(start);
    }

    return result;
}

void print_result(const EngineBenchResult& r){
    std::cout << "  " << std::left << std::setw(14) << r.name
              << "round trip: " << std::right << std::setw(10) << std::fixed << std::setprecision(4) << r.round_trip_ms << " ms   "
              << "mul: " << std::setw(10) << r.mul_ms << " ms   "
              << "x264 mul total: " << std::setw(10) << std::setprecision(1) << r.x264_mul_ms << " ms"
              << (r.x264_extrapolated ? "  (extrapolated from mul time, not measured directly)" : "")
              << std::endl;
}

void bench_case(int32_t degree, int64_t modulus, int32_t trials, int32_t naive_trials){
    std::cout << "=== degree=" << degree << " modulus=" << modulus
               << " (trials=" << trials << ", naive trials=" << naive_trials << ") ===" << std::endl;

    auto naive = std::shared_ptr<PolynomialMultiplicationEngine>(new NaiveNegacyclicMultiplicationEngine(degree, modulus));
    print_result(bench_engine("Naive", naive, degree, modulus, naive_trials, /*extrapolate_x264=*/true));

    auto portable = std::shared_ptr<PolynomialMultiplicationEngine>(new PortableNTTEngine(degree, modulus));
    print_result(bench_engine("PortableNTT", portable, degree, modulus, trials, /*extrapolate_x264=*/false));

#if defined(USE_IntelHexl)
    auto hexl = std::shared_ptr<PolynomialMultiplicationEngine>(new IntelHexlNTTEngine(degree, modulus));
    print_result(bench_engine("HEXL", hexl, degree, modulus, trials, /*extrapolate_x264=*/false));
#else
    std::cout << "  HEXL           (skipped -- build with -DNTT_ENGINE=Hexl to include it)" << std::endl;
#endif

    std::cout << std::endl;
}

int main(){
    // The two real moduli from this project's parameters, both verified
    // NTT-friendly (q = 1 mod 2n) for n up to at least 4096.
    constexpr int64_t kQ1 = 281474976694273LL;
    constexpr int64_t kQ2 = 102445068478701569LL;

    std::cout << "Polynomial multiplication engine benchmark" << std::endl;
    std::cout << "(times are per-operation averages except the x264 column, which is a total;" << std::endl;
    std::cout << " Naive uses fewer trials since it is O(n^2) and much slower)" << std::endl << std::endl;

    bench_case(2048, kQ1, 30, 5);
    bench_case(2048, kQ2, 30, 5);
    bench_case(4096, kQ1, 20, 3);
    bench_case(4096, kQ2, 20, 3);

    return 0;
}
