import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.append(str(ROOT))

from app.core.llm.rag import retrieve_context

def main():
    print("Testing FAISS RAG retrieval...")
    print("\n--- Test 1: SMB EternalBlue ---")
    res1 = retrieve_context("Comment exploiter ms17-010 eternalblue sur le port 445 ?")
    print(res1[:500] if res1 else "Aucun résultat")
    
    print("\n--- Test 2: vsftpd ---")
    res2 = retrieve_context("Exploit vsftpd 2.3.4 backdoor")
    print(res2[:500] if res2 else "Aucun résultat")

if __name__ == "__main__":
    main()
