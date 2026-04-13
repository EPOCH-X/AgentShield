from datasets import load_dataset

ds = load_dataset("gabrielchua/system-prompt-leakage", split="train[:3]")

print(ds.column_names)
print(ds[0])