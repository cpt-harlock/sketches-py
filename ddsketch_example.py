from ddsketch.ddsketch import *
import numpy as np
import matplotlib.pyplot as plt

if __name__ == "__main__":
    sketch = FixedSizeDDSketch(100, 0.1, bin_limit=50)
    values = np.random.normal(50, 10, 10000)
    for v in values:
        sketch.add(v)
    estimated_quantiles = [sketch.get_quantile_value(k) for k in [0.25, 0.5, 0.9, 1]]
    true_quantiles = np.quantile(values, [0.25, 0.5, 0.9, 1])
    print(np.array(estimated_quantiles))
    print(true_quantiles)
    print(sketch.store.bin_limit)
    print(sketch.mapping.relative_accuracy)
    histogram, bins = np.histogram(values)
    plt.hist(values, bins='auto')
    plt.show()
