# Mirage Documentation

> **Adversarial ML Security Toolkit**

Mirage provides comprehensive tools for testing, defending, and understanding machine learning model vulnerabilities. Attack simulation, defense implementation, and robustness evaluation all in one framework.

## Overview

Mirage delivers cutting-edge ML security:

- **Attack Library**: FGSM, PGD, DeepFool, C&W, AutoAttack
- **Defense Mechanisms**: Adversarial training, input purification
- **Robustness Metrics**: Comprehensive model evaluation
- **Model Support**: PyTorch, TensorFlow, ONNX, Julia Flux

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      MIRAGE FRAMEWORK                        │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │                   Attack Engine                       │   │
│  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌───────────┐  │   │
│  │  │  FGSM  │  │  PGD   │  │DeepFool│  │ C&W/Auto  │  │   │
│  │  └────────┘  └────────┘  └────────┘  └───────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  Defense Engine                       │   │
│  │  ┌────────────────┐  ┌─────────────┐  ┌───────────┐  │   │
│  │  │ Adv. Training  │  │ Purification│  │ Detection │  │   │
│  │  └────────────────┘  └─────────────┘  └───────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │               Evaluation & Metrics                    │   │
│  │                                                       │   │
│  │  Robustness Score │ Attack Success Rate │ Transferability│
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```julia
using Mirage

# Load a model
model = load_model("classifier.onnx")

# Load test data
X_test, y_test = load_test_data("test_data.npz")

# Evaluate clean accuracy
clean_acc = evaluate_accuracy(model, X_test, y_test)
println("Clean accuracy: $(round(clean_acc * 100, digits=1))%")

# Run FGSM attack
fgsm = FGSM(epsilon=0.03)
adv_examples = generate_adversarial(model, X_test, y_test, fgsm)

# Evaluate adversarial accuracy
adv_acc = evaluate_accuracy(model, adv_examples, y_test)
println("Adversarial accuracy: $(round(adv_acc * 100, digits=1))%")

# Calculate robustness
robustness = 1.0 - (clean_acc - adv_acc)
println("Robustness score: $(round(robustness * 100, digits=1))%")
```

## Attack Methods

### Fast Gradient Sign Method (FGSM)

Single-step perturbation attack:

```julia
using Mirage.Attacks

# Basic FGSM
fgsm = FGSM(epsilon=0.03)
adversarial = attack(model, x, y, fgsm)

# Targeted FGSM
targeted_fgsm = FGSM(epsilon=0.03, targeted=true, target_class=5)
adversarial = attack(model, x, y, targeted_fgsm)
```

### Projected Gradient Descent (PGD)

Iterative attack, stronger than FGSM:

```julia
# PGD with L∞ norm
pgd_linf = PGD(
    epsilon = 0.03,
    step_size = 0.007,
    iterations = 40,
    norm = :linf,
    random_start = true
)

# PGD with L2 norm
pgd_l2 = PGD(
    epsilon = 1.0,
    step_size = 0.1,
    iterations = 40,
    norm = :l2
)

adversarial = attack(model, x, y, pgd_linf)
```

### DeepFool

Minimal perturbation attack:

```julia
deepfool = DeepFool(
    max_iterations = 50,
    overshoot = 0.02,
    norm = :l2
)

adversarial = attack(model, x, y, deepfool)
# Returns adversarial with minimal perturbation
```

### Carlini & Wagner (C&W)

Optimization-based attack:

```julia
cw = CarliniWagner(
    confidence = 0,
    learning_rate = 0.01,
    iterations = 1000,
    binary_search_steps = 9,
    norm = :l2,
    abort_early = true
)

adversarial = attack(model, x, y, cw)
# Highly effective, slow but finds small perturbations
```

### AutoAttack

Ensemble of attacks:

```julia
autoattack = AutoAttack(
    epsilon = 0.03,
    attacks = [:apgd_ce, :apgd_dlr, :fab, :square],
    version = :standard  # or :plus, :rand
)

adversarial = attack(model, x, y, autoattack)
# Most reliable robustness evaluation
```

### Attack Comparison

| Attack | Speed | Strength | Perturbation |
|--------|-------|----------|--------------|
| FGSM | ⚡⚡⚡ | ⭐⭐ | Larger |
| PGD | ⚡⚡ | ⭐⭐⭐ | Medium |
| DeepFool | ⚡⚡ | ⭐⭐⭐ | Minimal |
| C&W | ⚡ | ⭐⭐⭐⭐ | Minimal |
| AutoAttack | ⚡ | ⭐⭐⭐⭐⭐ | Varies |

## Defense Methods

### Adversarial Training

```julia
using Mirage.Defense

# Standard adversarial training
defense = AdversarialTraining(
    attack = PGD(epsilon=0.03, iterations=7),
    mix_ratio = 0.5  # 50% clean, 50% adversarial
)

robust_model = train_with_defense(model, train_data, defense,
    epochs = 100,
    optimizer = Adam(lr=0.001)
)
```

### TRADES (TRadeoff-inspired Adversarial DEfense)

```julia
trades = TRADES(
    epsilon = 0.03,
    step_size = 0.007,
    iterations = 10,
    beta = 6.0  # Robustness-accuracy tradeoff
)

robust_model = train_with_defense(model, train_data, trades)
```

### Input Purification

```julia
# Feature squeezing
squeezer = FeatureSqueezing(bit_depth=4)
purified = purify(x, squeezer)

# JPEG compression
jpeg_defense = JPEGCompression(quality=75)
purified = purify(x, jpeg_defense)

# Spatial smoothing
smoother = SpatialSmoothing(kernel_size=3)
purified = purify(x, smoother)

# Combine defenses
ensemble = DefenseEnsemble([squeezer, jpeg_defense, smoother])
purified = purify(x, ensemble)
```

### Adversarial Detection

```julia
detector = AdversarialDetector(
    method = :lid,  # Local Intrinsic Dimensionality
    threshold = 0.8
)

# Train detector
train_detector!(detector, clean_samples, adversarial_samples)

# Detect adversarial inputs
is_adversarial = detect(detector, x)
# => true/false for each sample
```

### Certified Defense

```julia
# Randomized smoothing
smoother = RandomizedSmoothing(
    base_classifier = model,
    sigma = 0.25,
    n_samples = 1000
)

# Get certified prediction
pred, radius = certified_predict(smoother, x)
# radius = certified L2 robustness radius
```

## Robustness Evaluation

### Comprehensive Evaluation

```julia
using Mirage.Evaluation

# Full robustness report
report = evaluate_robustness(model, test_data,
    attacks = [
        FGSM(epsilon=0.03),
        PGD(epsilon=0.03, iterations=20),
        PGD(epsilon=0.03, iterations=100),
        AutoAttack(epsilon=0.03)
    ],
    metrics = [:accuracy, :success_rate, :avg_perturbation, :confidence_drop]
)

# Print summary
println(report)

# Export report
write("robustness_report.md", export_markdown(report))
write("robustness_report.json", export_json(report))
```

### Metrics

```julia
# Attack success rate
asr = attack_success_rate(model, X_test, y_test, attack)

# Average perturbation
avg_perturb = average_perturbation(X_clean, X_adversarial, norm=:l2)

# Confidence change
conf_drop = confidence_drop(model, X_clean, X_adversarial)

# Robustness curve (accuracy vs epsilon)
curve = robustness_curve(model, X_test, y_test,
    attack = PGD,
    epsilons = 0:0.005:0.1
)
plot(curve.epsilons, curve.accuracies)
```

### Transferability Analysis

```julia
# Test transferability between models
models = [model_a, model_b, model_c]
transfer_matrix = transferability_matrix(models, X_test, y_test, attack)

#          Model A  Model B  Model C
# Model A    1.00     0.67     0.54
# Model B    0.71     1.00     0.59
# Model C    0.48     0.52     1.00
```

## Model Support

### PyTorch

```julia
# Load PyTorch model
model = load_pytorch_model("model.pt")

# Or from TorchScript
model = load_torchscript("model_scripted.pt")
```

### TensorFlow

```julia
# Load SavedModel
model = load_tensorflow_model("saved_model/")

# Or from H5
model = load_keras_model("model.h5")
```

### ONNX

```julia
# Universal format
model = load_onnx_model("model.onnx")
```

### Julia Flux

```julia
using Flux

# Native Julia models
model = load_flux_model("model.bson")

# Or wrap existing Flux model
mirage_model = MirageModel(flux_model)
```

## Visualization

```julia
using Mirage.Visualization

# Visualize perturbations
plot_perturbation(x_clean, x_adversarial)

# Visualize attack progress
plot_attack_progress(attack_history)

# Visualize decision boundary
plot_decision_boundary(model, X, y, dims=[1,2])

# Saliency maps
saliency = compute_saliency(model, x)
plot_saliency(x, saliency)
```

## Batch Processing

```julia
# Evaluate large dataset efficiently
results = batch_evaluate(model, test_data,
    attacks = [FGSM(0.03), PGD(0.03)],
    batch_size = 64,
    n_workers = 4,
    progress = true
)
```

## Configuration

```julia
Mirage.configure(
    # Computation
    device = :gpu,  # :cpu or :gpu
    precision = Float32,
    batch_size = 64,
    
    # Attacks
    default_epsilon = 0.03,
    default_iterations = 20,
    clip_min = 0.0,
    clip_max = 1.0,
    
    # Logging
    verbose = true,
    log_level = :info,
    progress_bar = true
)
```

## Best Practices

### 1. Start Simple

```julia
# Start with FGSM
fgsm_result = attack(model, x, y, FGSM(0.03))

# If model is robust, try stronger attacks
pgd_result = attack(model, x, y, PGD(0.03, iterations=100))

# Final evaluation with AutoAttack
auto_result = attack(model, x, y, AutoAttack(0.03))
```

### 2. Use Appropriate Epsilon

| Domain | Typical ε (L∞) |
|--------|---------------|
| MNIST | 0.3 |
| CIFAR-10 | 0.03 (8/255) |
| ImageNet | 0.003 (1/255) |

### 3. Defense Combinations

```julia
# Layer defenses
robust_pipeline = Pipeline([
    InputPurification(jpeg_quality=80),
    AdversariallyTrainedModel(model),
    AdversarialDetector(threshold=0.95),
    OutputSmoothing(temperature=2.0)
])
```

## Performance

| Operation | GPU | CPU |
|-----------|-----|-----|
| FGSM (batch 64) | 5ms | 50ms |
| PGD-20 (batch 64) | 80ms | 800ms |
| PGD-100 (batch 64) | 400ms | 4s |
| AutoAttack (batch 64) | 30s | 5min |
| Adv. training (epoch) | 2min | 20min |

## API Reference

See the complete [API Reference](api.md) for detailed function signatures.

---

[Back to Main Documentation](../../README.md)
