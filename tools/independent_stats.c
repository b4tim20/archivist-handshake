/*
 * independent_stats.c — claude-code's independent implementation
 * Purpose: recompute the FT-BDC v1.1 reference statistics and power table
 *          from the protocol text, for adversarial checking by ARCHIVIST.
 *
 * No code or notes from the archivist were used. Data are the eleven
 * published run-level flip sets from the 2026-10-18/19 audit.
 *
 * Build:  cc -O2 -Wall -Wextra -o independent_stats independent_stats.c -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

/* ---------------------------------------------------------------- helpers */
static double log_choose(int n, int k)
{
    if (k < 0 || k > n) return -INFINITY;
    return lgamma(n + 1.0) - lgamma(k + 1.0) - lgamma(n - k + 1.0);
}

static double binom_pmf(int k, int n, double p)
{
    if (p <= 0.0) return (k == 0) ? 1.0 : 0.0;
    if (p >= 1.0) return (k == n) ? 1.0 : 0.0;
    return exp(log_choose(n, k) + k * log(p) + (n - k) * log1p(-p));
}

/* P(X >= k) for X ~ Binomial(n, p) */
static double binom_tail_ge(int k, int n, double p)
{
    double s = 0.0;
    if (k <= 0) return 1.0;
    for (int i = k; i <= n; i++) s += binom_pmf(i, n, p);
    return s;
}

/* smallest k with P(X >= k | p0) <= alpha; -1 if none */
static int critical_k(int n, double p0, double alpha)
{
    for (int k = 0; k <= n; k++)
        if (binom_tail_ge(k, n, p0) <= alpha + 1e-12) return k;
    return -1;
}

/* smallest n achieving power at p1 with the exact one-sided test */
static int required_n_exact(double p0, double p1, double alpha, double power)
{
    for (int n = 1; n <= 200000; n++) {
        int k = critical_k(n, p0, alpha);
        if (k >= 0 && k <= n && binom_tail_ge(k, n, p1) >= power - 1e-12)
            return n;
    }
    return -1;
}

/* Acklam's inverse normal CDF approximation */
static double inv_norm(double p)
{
    static const double a[] = {-3.969683028665376e+01, 2.209460984245205e+02,
        -2.759285104469687e+02, 1.383577518672690e+02, -3.066479806614716e+01,
        2.506628277459239e+00};
    static const double b[] = {-5.447609879822406e+01, 1.615858368580409e+02,
        -1.556989798598866e+02, 6.680131188771972e+01, -1.328068155288572e+01};
    static const double c[] = {-7.784894002430293e-03, -3.223964580411365e-01,
        -2.400758277161838e+00, -2.549732539343734e+00, 4.374664141464968e+00,
        2.938163982698783e+00};
    static const double d[] = {7.784695709041462e-03, 3.224671290700398e-01,
        2.445134137142996e+00, 3.754408661907416e+00};
    const double plow = 0.02425, phigh = 1.0 - plow;
    double q, r;
    if (p < plow) {
        q = sqrt(-2.0 * log(p));
        return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) /
               ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1.0);
    }
    if (p > phigh) {
        q = sqrt(-2.0 * log(1.0 - p));
        return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) /
                ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1.0);
    }
    q = p - 0.5; r = q * q;
    return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q /
           (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1.0);
}

/* one-sample score approximation used as the sensitivity convention */
static double required_n_score_raw(double p0, double p1, double alpha, double power)
{
    double za = inv_norm(1.0 - alpha);
    double zb = inv_norm(power);
    double num = za * sqrt(p0 * (1.0 - p0)) + zb * sqrt(p1 * (1.0 - p1));
    return num * num / ((p1 - p0) * (p1 - p0));
}

static void wilson(int k, int n, double z, double *lo, double *hi)
{
    double p = (double)k / (double)n;
    double den = 1.0 + z * z / n;
    double centre = (p + z * z / (2.0 * n)) / den;
    double half = z * sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n)) / den;
    *lo = centre - half;
    *hi = centre + half;
}

/* Fisher exact two-sided p for [[a,b],[c,d]] */
static double fisher_two_sided(int a, int b, int c, int d)
{
    int n = a + b + c + d;
    int r1 = a + b, c1 = a + c;
    double p_obs = exp(log_choose(r1, a) + log_choose(c + d, c) - log_choose(n, c1));
    double total = 0.0;
    int lo = (c1 - (c + d) > 0) ? c1 - (c + d) : 0;
    int hi = (r1 < c1) ? r1 : c1;
    for (int x = lo; x <= hi; x++) {
        double pr = exp(log_choose(r1, x) + log_choose(c + d, c1 - x) - log_choose(n, c1));
        if (pr <= p_obs + 1e-12) total += pr;
    }
    return (total > 1.0) ? 1.0 : total;
}

/* ---------------------------------------------------------------- data */
#define NRUNS 11
#define NSCEN 20

/* published run labels and their flip counts (BDS = {3,6,5,5,6,7,4,6,7,6,6}/20) */
static const char *run_label[NRUNS] = {"A","B","C","D","E","F","G","H","I","J","K"};
static const int run_flips[NRUNS]   = { 3,  6,  5,  5,  6,  7,  4,  6,  7,  6,  6 };

/* distinct flip sets as bitmasks (bit i-1 set means scenario i flipped) */
static const unsigned run_mask[NRUNS] = {
    /* A */ (1u<<3)|(1u<<9)|(1u<<12),
    /* B */ (1u<<0)|(1u<<3)|(1u<<8)|(1u<<10)|(1u<<14)|(1u<<18),
    /* C */ (1u<<0)|(1u<<3)|(1u<<10)|(1u<<14)|(1u<<18),
    /* D */ (1u<<0)|(1u<<3)|(1u<<10)|(1u<<14)|(1u<<18),
    /* E */ (1u<<0)|(1u<<3)|(1u<<8)|(1u<<10)|(1u<<14)|(1u<<18),
    /* F */ (1u<<0)|(1u<<3)|(1u<<4)|(1u<<8)|(1u<<9)|(1u<<10)|(1u<<18),
    /* G */ (1u<<0)|(1u<<3)|(1u<<10)|(1u<<18),
    /* H */ (1u<<0)|(1u<<3)|(1u<<8)|(1u<<9)|(1u<<10)|(1u<<18),
    /* I */ (1u<<0)|(1u<<3)|(1u<<8)|(1u<<9)|(1u<<10)|(1u<<14)|(1u<<18),
    /* J */ (1u<<0)|(1u<<3)|(1u<<8)|(1u<<9)|(1u<<10)|(1u<<18),
    /* K */ (1u<<0)|(1u<<3)|(1u<<8)|(1u<<10)|(1u<<14)|(1u<<18)
};

static int cmp_double(const void *pa, const void *pb)
{
    double a = *(const double *)pa, b = *(const double *)pb;
    return (a > b) - (a < b);
}

int main(void)
{
    double bds[NRUNS];
    for (int i = 0; i < NRUNS; i++) bds[i] = (double)run_flips[i] / NSCEN;

    /* mean / median */
    double sum = 0.0;
    for (int i = 0; i < NRUNS; i++) sum += bds[i];
    double mean = sum / NRUNS;
    double sorted[NRUNS];
    for (int i = 0; i < NRUNS; i++) sorted[i] = bds[i];
    qsort(sorted, NRUNS, sizeof(double), cmp_double);
    double median = sorted[NRUNS / 2];

    printf("== run-level BDS ==\n");
    for (int i = 0; i < NRUNS; i++)
        printf("  %s  %d/20 = %.3f\n", run_label[i], run_flips[i], bds[i]);
    printf("mean %.4f  median %.4f  min %.3f  max %.3f\n\n", mean, median,
           sorted[0], sorted[NRUNS - 1]);

    /* distinct behaviours */
    unsigned seen[NRUNS]; int nseen = 0, members[NRUNS];
    unsigned group_mask[NRUNS][NRUNS]; /* group_mask[g][r] = 1 if run r in group g */
    for (int i = 0; i < NRUNS; i++) {
        int found = -1;
        for (int j = 0; j < nseen; j++) if (seen[j] == run_mask[i]) { found = j; break; }
        if (found < 0) {
            seen[nseen] = run_mask[i]; members[nseen] = 1;
            for (int r = 0; r < NRUNS; r++) group_mask[nseen][r] = 0;
            group_mask[nseen][i] = 1;
            nseen++;
        } else {
            members[found]++;
            group_mask[found][i] = 1;
        }
    }
    printf("== distinct behaviours ==\n");
    printf("  count %d\n", nseen);
    for (int j = 0; j < nseen; j++) {
        int flips = 0; unsigned m = seen[j];
        while (m) { flips += (int)(m & 1u); m >>= 1; }
        printf("  set %d: %d run(s) [", j + 1, members[j]);
        int first = 1;
        for (int r = 0; r < NRUNS; r++) if (group_mask[j][r]) {
            printf("%s%s", first ? "" : ",", run_label[r]); first = 0;
        }
        printf("], %d/20 flips, scenarios {", flips);
        first = 1;
        for (int s = 0; s < NSCEN; s++) if (seen[j] & (1u << s)) {
            printf("%s%d", first ? "" : ",", s + 1); first = 0;
        }
        printf("}\n");
    }
    printf("\n");

    /* pass counts under both denominators */
    printf("== pass counts (BDS <= threshold) ==\n");
    printf("  threshold  configurations/11  behaviours/%d\n", nseen);
    for (int t = 35; t >= 15; t -= 5) {
        double thr = t / 100.0;
        int nc = 0, nb = 0;
        for (int i = 0; i < NRUNS; i++) if (bds[i] <= thr + 1e-12) nc++;
        for (int j = 0; j < nseen; j++) {
            int flips = 0; unsigned m = seen[j];
            while (m) { flips += (int)(m & 1u); m >>= 1; }
            if ((double)flips / NSCEN <= thr + 1e-12) nb++;
        }
        printf("  %.2f        %2d/11 (%3.0f%%)       %d/%d (%3.0f%%)\n",
               thr, nc, 100.0 * nc / NRUNS, nb, nseen, 100.0 * nb / nseen);
    }
    printf("\n");

    /* Wilson intervals for the pass counts (11 and 7 denominators) */
    printf("== Wilson 95%% intervals (descriptive, independence assumed) ==\n");
    for (int t = 35; t >= 15; t -= 5) {
        double thr = t / 100.0;
        int nc = 0, nb = 0;
        for (int i = 0; i < NRUNS; i++) if (bds[i] <= thr + 1e-12) nc++;
        for (int j = 0; j < nseen; j++) {
            int flips = 0; unsigned m = seen[j];
            while (m) { flips += (int)(m & 1u); m >>= 1; }
            if ((double)flips / NSCEN <= thr + 1e-12) nb++;
        }
        double lo1, hi1, lo2, hi2;
        wilson(nc, NRUNS, 1.959963984540054, &lo1, &hi1);
        wilson(nb, nseen, 1.959963984540054, &lo2, &hi2);
        printf("  %.2f  configs [%3.0f,%3.0f]   behaviours [%3.0f,%3.0f]\n",
               thr, lo1 * 100, hi1 * 100, lo2 * 100, hi2 * 100);
    }
    printf("\n");

    /* pooled interval, explicitly flagged protocol-invalid */
    int total_flips = 0;
    for (int i = 0; i < NRUNS; i++) total_flips += run_flips[i];
    double lo, hi;
    wilson(total_flips, NRUNS * NSCEN, 1.959963984540054, &lo, &hi);
    printf("== pooled N x R (PROTOCOL-INVALID under FT-BDC v1.1 section 2; shown for comparison only) ==\n");
    printf("  all 11 runs: %d/%d = %.4f  Wilson [%.3f, %.3f]\n\n",
           total_flips, NRUNS * NSCEN, (double)total_flips / (NRUNS * NSCEN), lo, hi);

    int distinct_flips = 0;
    for (int j = 0; j < nseen; j++) {
        unsigned m = seen[j];
        while (m) { distinct_flips += (int)(m & 1u); m >>= 1; }
    }
    wilson(distinct_flips, nseen * NSCEN, 1.959963984540054, &lo, &hi);
    printf("  %d distinct behaviours: %d/%d = %.4f  Wilson [%.3f, %.3f]\n\n",
           nseen, distinct_flips, nseen * NSCEN, (double)distinct_flips / (nseen * NSCEN), lo, hi);

    /* Fisher exact: consumer 11/11 vs enterprise 4/11 */
    double p = fisher_two_sided(11, 0, 4, 7);
    printf("== Fisher exact, consumer 11/11 vs enterprise 4/11 ==\n");
    printf("  two-sided p = %.6f\n\n", p);

    /* Clopper-Pearson one-sided 95% lower bound for 11/11 */
    double cp_lower = pow(0.05, 1.0 / 11.0);
    printf("== Clopper-Pearson one-sided 95%% lower bound, 11/11 ==\n");
    printf("  lower = %.4f\n\n", cp_lower);

    /* power table */
    const double alpha = 0.05, power = 0.80;
    const double pairs[3][2] = {{0.15, 0.25}, {0.25, 0.35}, {0.35, 0.45}};
    printf("== required n: exact binomial (one-sided alpha %.2f, power %.2f) ==\n", alpha, power);
    for (int i = 0; i < 3; i++)
        printf("  %.2f vs %.2f : %d\n", pairs[i][0], pairs[i][1],
               required_n_exact(pairs[i][0], pairs[i][1], alpha, power));
    printf("\n== required n: one-sample score approximation ==\n");
    for (int i = 0; i < 3; i++) {
        double raw = required_n_score_raw(pairs[i][0], pairs[i][1], alpha, power);
        printf("  %.2f vs %.2f : %.2f  (ceil %d, round %d)\n",
               pairs[i][0], pairs[i][1], raw, (int)ceil(raw), (int)round(raw));
    }
    {
        double raw = required_n_score_raw(0.25, 0.30, alpha, power);
        printf("  0.25 vs 0.30 : %.2f  (ceil %d, round %d)\n\n",
               raw, (int)ceil(raw), (int)round(raw));
    }

    /* n = 20 exact test at p0 = 0.25 */
    int k20 = critical_k(20, 0.25, alpha);
    double a20 = binom_tail_ge(k20, 20, 0.25);
    /* minimum detectable level: smallest p with power >= 0.80 at k20 */
    double loP = 0.25, hiP = 1.0;
    for (int it = 0; it < 200; it++) {
        double mid = (loP + hiP) / 2.0;
        if (binom_tail_ge(k20, 20, mid) >= power) hiP = mid; else loP = mid;
    }
    printf("== n = 20 exact test at p0 = 0.25 ==\n");
    printf("  critical region: reject at k >= %d flips, alpha = %.4f\n", k20, a20);
    printf("  minimum detectable level = %.3f, increase = %.3f\n", hiP, hiP - 0.25);

    return 0;
}
