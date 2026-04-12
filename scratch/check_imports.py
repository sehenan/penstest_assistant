import sys
print("Starting import check...")
try:
    import sentence_transformers
    print("sentence_transformers imported successfully")
except ImportError:
    print("sentence_transformers NOT found")
except Exception as e:
    print(f"Error importing sentence_transformers: {e}")

try:
    from sentence_transformers import SentenceTransformer
    print("SentenceTransformer imported successfully")
except ImportError:
    print("SentenceTransformer NOT found")
except Exception as e:
    print(f"Error importing SentenceTransformer: {e}")

print("Done.")
