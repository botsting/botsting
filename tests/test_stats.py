import pytest

from kritalon.core.stats import make_rate, wilson_interval


def test_wilson_known_values():
    low, high = wilson_interval(5, 5)
    assert low == pytest.approx(0.5655, abs=1e-4) and high == 1.0
    low, high = wilson_interval(0, 5)
    assert low == 0.0 and high == pytest.approx(0.4345, abs=1e-4)
    low, high = wilson_interval(3, 10)
    assert low == pytest.approx(0.1078, abs=1e-4) and high == pytest.approx(0.6032, abs=1e-4)


def test_wilson_edge_cases():
    assert wilson_interval(0, 0) is None
    with pytest.raises(ValueError):
        wilson_interval(6, 5)
    with pytest.raises(ValueError):
        wilson_interval(-1, 5)


def test_interval_contains_the_observed_rate():
    for trials in range(1, 30):
        for successes in range(trials + 1):
            low, high = wilson_interval(successes, trials)
            assert 0.0 <= low <= successes / trials <= high <= 1.0


def test_make_rate_keeps_errors_out_of_the_denominator():
    rate = make_rate(3, 4, errors=1)
    assert (rate.successes, rate.trials, rate.errors) == (3, 4, 1)
    assert rate.rate == 0.75
    assert rate.interval_method == "wilson-95"
    empty = make_rate(0, 0, errors=5)
    assert empty.rate is None and empty.interval_low is None and empty.interval_high is None
