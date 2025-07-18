#include "kalman.h"
#include "stdbool.h"

void kalman_init(kalman_t *filter,
                     float initial_process_noise,
                     float initial_measurement_noise,
                     float initial_estimated_error,
                     float initial_value) {    
    filter->process_noise = initial_process_noise;
    filter->measurement_noise = initial_measurement_noise;
    filter->estimated_error = initial_estimated_error;
    filter->state_estimate = initial_value;
    filter->is_initialized = (initial_value != 0.0f) || (initial_estimated_error != 1.0f); 
}

float kalman_filter(kalman_t *filter, float measurement) {
    if (!filter->is_initialized) {
        filter->state_estimate = measurement;
        if (filter->estimated_error == 1.0f) {
             filter->estimated_error = measurement * measurement * 0.25f;
             if (filter->estimated_error < 0.001f) filter->estimated_error = 0.001f;
        }
        filter->is_initialized = true;
        return filter->state_estimate;
    }
    filter->estimated_error += filter->process_noise; 
    float kalman_gain = filter->estimated_error / (filter->estimated_error + filter->measurement_noise);
    filter->state_estimate = filter->state_estimate + kalman_gain * (measurement - filter->state_estimate);
    filter->estimated_error = (1.0f - kalman_gain) * filter->estimated_error;
    return filter->state_estimate;
}

void kalman_reset(kalman_t *filter) {
    filter->is_initialized = false;
    filter->state_estimate = 0.0f;
    filter->estimated_error = 1.0f;
}

float kalman_get_process_noise(const kalman_t *filter) {
    return filter->process_noise;
}

float kalman_get_measurement_noise(const kalman_t *filter) {
    return filter->measurement_noise;
}

float kalman_get_estimated_error(const kalman_t *filter) {
    return filter->estimated_error;
}

float kalman_get_state_estimate(const kalman_t *filter) {
    return filter->state_estimate;
}
