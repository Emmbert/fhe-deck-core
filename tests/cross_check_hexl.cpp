#include "fhe_deck.h"
#include "math/portable_ntt_engine.h"
#include "math/intel_hexl_engine.h"

#include <iostream>
#include <random>

using namespace FHEDeck;

int main(){
    std::mt19937_64 rng(7);
    int fails = 0;

    for(int32_t degree : {2048, 4096}){
        for(int64_t modulus : {281474976694273LL, 102445068478701569LL}){
            PortableNTTEngine portable(degree, modulus);
            IntelHexlNTTEngine hexl(degree, modulus);
            std::uniform_int_distribution<int64_t> dist(0, modulus - 1);

            for(int trial = 0; trial < 20; ++trial){
                Polynomial a(degree, modulus);
                Polynomial b(degree, modulus);
                for(int32_t i = 0; i < degree; ++i){ a[i] = dist(rng); b[i] = dist(rng); }

                auto a_eval_p = portable.init_polynomial_eval_form();
                auto b_eval_p = portable.init_polynomial_eval_form();
                auto out_eval_p = portable.init_polynomial_eval_form();
                auto a_eval_h = hexl.init_polynomial_eval_form();
                auto b_eval_h = hexl.init_polynomial_eval_form();
                auto out_eval_h = hexl.init_polynomial_eval_form();

                portable.to_eval(*a_eval_p, a);
                portable.to_eval(*b_eval_p, b);
                portable.mul(*out_eval_p, *a_eval_p, *b_eval_p);
                Polynomial out_p(degree, modulus);
                portable.to_coef(out_p, *out_eval_p);

                hexl.to_eval(*a_eval_h, a);
                hexl.to_eval(*b_eval_h, b);
                hexl.mul(*out_eval_h, *a_eval_h, *b_eval_h);
                Polynomial out_h(degree, modulus);
                hexl.to_coef(out_h, *out_eval_h);

                if(out_p != out_h){
                    std::cout << "MISMATCH degree=" << degree << " modulus=" << modulus << " trial=" << trial << std::endl;
                    fails++;
                }
            }
            std::cout << "degree=" << degree << " modulus=" << modulus << ": 20/20 trials checked (PortableNTT vs HEXL, mul output)" << std::endl;
        }
    }

    if(fails == 0){
        std::cout << "ALL PASS: PortableNTTEngine output matches IntelHexlNTTEngine exactly." << std::endl;
        return 0;
    }
    std::cout << fails << " MISMATCHES FOUND" << std::endl;
    return 1;
}
