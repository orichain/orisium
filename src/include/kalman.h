#ifndef KALMAN_H
#define KALMAN_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    float process_noise;       // Q: Variansi noise proses
    float measurement_noise;   // R: Variansi noise pengukuran
    float estimated_error;     // P: Kovariansi error estimasi
    float state_estimate;      // X: Estimasi state
    bool is_initialized;       // Status inisialisasi
} kalman_t;

static inline void kalman_init(
    kalman_t *filter,
    float initial_process_noise,
    float initial_measurement_noise,
    float initial_estimated_error,
    float initial_value
) {
    filter->process_noise      = initial_process_noise;
    filter->measurement_noise  = initial_measurement_noise;
    filter->estimated_error    = initial_estimated_error;
    filter->state_estimate     = initial_value;
    filter->is_initialized     = (initial_value != 0.0f) || (initial_estimated_error != 1.0f);
}

static inline float kalman_filter(kalman_t *filter, float measurement) {
    if (!filter->is_initialized) {
        filter->state_estimate = measurement;

        if (filter->estimated_error == 1.0f) {
            float e = 0.25f * measurement * measurement;
            filter->estimated_error = (e < 0.001f) ? 0.001f : e;
        }

        filter->is_initialized = true;
        return filter->state_estimate;
    }

    // Prediction step
    filter->estimated_error += filter->process_noise;

    // Kalman Gain
    float denominator = filter->estimated_error + filter->measurement_noise;
    float kalman_gain = (denominator != 0.0f) ? (filter->estimated_error / denominator) : 0.0f;

    // Correction step
    filter->state_estimate += kalman_gain * (measurement - filter->state_estimate);
    filter->estimated_error *= (1.0f - kalman_gain);

    return filter->state_estimate;
}

static inline void kalman_reset(kalman_t *filter) {
    filter->is_initialized  = false;
    filter->state_estimate  = 0.0f;
    filter->estimated_error = 1.0f;
}

static inline float kalman_get_process_noise(const kalman_t *filter) {
    return filter->process_noise;
}

static inline float kalman_get_measurement_noise(const kalman_t *filter) {
    return filter->measurement_noise;
}

static inline float kalman_get_estimated_error(const kalman_t *filter) {
    return filter->estimated_error;
}

static inline float kalman_get_state_estimate(const kalman_t *filter) {
    return filter->state_estimate;
}

#endif
