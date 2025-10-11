import os
import evaluate
import pandas as pd

# Paths
pred_dir = r"D:\VulnScanAI_Chatbot\Model_performance\predictions"
ref_dir = r"D:\VulnScanAI_Chatbot\Model_performance\references"
num_tests = 10  # adjust based on how many tests you have

# Load metrics
bleu = evaluate.load("bleu")
rouge = evaluate.load("rouge")

# Store results
results = []

for i in range(1, num_tests + 1):
    pred_path = os.path.join(pred_dir, f"prediction_{i}.txt")
    ref_path = os.path.join(ref_dir, f"reference_{i}.txt")

    # Read files
    with open(pred_path, "r", encoding="utf-8") as pf:
        predictions = [line.strip() for line in pf.readlines() if line.strip()]
    with open(ref_path, "r", encoding="utf-8") as rf:
        references = [line.strip() for line in rf.readlines() if line.strip()]

    # Ensure predictions and references have the same length
    min_len = min(len(predictions), len(references))
    if len(predictions) != len(references):
        print(f"Warning: Mismatch in prediction and reference lengths for test {i}. Using first {min_len} items from each.")
        predictions = predictions[:min_len]
        references = references[:min_len]

    # Skip if no valid pairs found
    if not predictions or not references:
        print(f"Skipping test {i}: No valid prediction-reference pairs found.")
        continue

    # Format references for BLEU (list of list of references)
    bleu_refs = [[ref] for ref in references]

    try:
        # Compute scores
        bleu_result = bleu.compute(predictions=predictions, references=bleu_refs)
        rouge_result = rouge.compute(predictions=predictions, references=references)

        # Append results to list
        results.append({
            "Test": f"Test_{i}",
            "BLEU": round(bleu_result["bleu"], 6),
            "ROUGE-1": round(rouge_result["rouge1"], 6),
            "ROUGE-2": round(rouge_result["rouge2"], 6),
            "ROUGE-L": round(rouge_result["rougeL"], 6)
        })
    except Exception as e:
        print(f"Error processing test {i}: {str(e)}")
        continue

# Convert to DataFrame for tabular view
if results:
    df = pd.DataFrame(results)
    print("\nEvaluation Results:")
    print(df.to_string(index=False))
else:
    print("No valid results to display.")
