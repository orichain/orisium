#ifndef KALMAN_H
#define KALMAN_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    float process_noise;     // Q: Variansi noise proses
    float measurement_noise; // R: Variansi noise pengukuran
    float estimated_error;   // P: Kovariansi error estimasi (ketidakpastian estimasi)
    float state_estimate;    // X: Estimasi state saat ini (nilai yang dihaluskan)
    bool is_initialized;     // Flag untuk menandakan apakah filter sudah diinisialisasi
} kalman_t;

void kalman_init(kalman_t *filter,
                     float initial_process_noise,
                     float initial_measurement_noise,
                     float initial_estimated_error,
                     float initial_value);
float kalman_filter(kalman_t *filter, float measurement);
void kalman_reset(kalman_t *filter);
float kalman_get_process_noise(const kalman_t *filter);
float kalman_get_measurement_noise(const kalman_t *filter);
float kalman_get_estimated_error(const kalman_t *filter);
float kalman_get_state_estimate(const kalman_t *filter);

#endif
