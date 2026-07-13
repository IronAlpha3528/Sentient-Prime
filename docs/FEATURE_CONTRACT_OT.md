# OT/ICS Feature Contract Reference

This document catalogs the behavioral features engineered for the OT Specialist pipeline.

## Feature Categories

### 1. Rolling Statistical Features
- **Features**: `*_mean`, `*_median`, `*_std`, `*_variance`, `*_min`, `*_max`, `*_range`, `*_p25`, `*_p75`, `*_iqr`, `*_cv`, `*_energy`, `*_entropy`
- **Description**: Computes amplitude statistics on process variables within a sliding 60-second window.
- **Why useful**: Detects when values go outside their normal statistical bounds (out of range, mean shifts, std variance spikes).
- **Used by**: Isolation Forest

### 2. Temporal & Trend Features
- **Features**: `*_first_diff_mean`, `*_rate_of_change`, `*_zero_crossings`
- **Description**: Measures the first order derivative and trend slope direction of signals.
- **Why useful**: Detects unexpected rapid pressure build-ups, level depletion, or signal frequency oscillations.
- **Used by**: Isolation Forest and LightGBM

### 3. Stability Features
- **Features**: `*_flatline_duration`, `*_oscillation_count`
- **Description**: Measures flatlining duration and local extrema oscillation frequency.
- **Why useful**: Identifies when a sensor is frozen (flatlining) due to loss of communication or controller lockups.
- **Used by**: Isolation Forest

### 4. Actuator state-change metrics
- **Features**: `*_state_changes`, `*_transition_rate`, `*_max_state_duration`
- **Description**: Quantifies the transition characteristics of binary or categorical control items.
- **Why useful**: Identifies rapid cycling (valve chattering) or actuator failures.
- **Used by**: Isolation Forest

### 5. Controller variance metrics
- **Features**: `*_variance`, `*_change_count`
- **Description**: Tracks adjustments made by PID controller outputs.
- **Why useful**: Explains if the control output is struggling to stabilize the system.
- **Used by**: Both

### 6. Cross-Sensor Pairwise Features
- **Features**: `cross_corr_*_vs_*`, `cross_cov_*_vs_*`
- **Description**: Pearson product-moment correlation and covariance coefficients between highly related process variables.
- **Why useful**: Extremely critical in identifying when physical process laws are violated (e.g. pressure increases while flow drops).
- **Used by**: Both
